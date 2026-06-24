using Microsoft.Extensions.Options;

namespace EmailOtp;

/// <summary>
/// Default <see cref="IEmailOtpService"/>. Holds the issue/verify contracts; storage atomicity
/// (single active slot, atomic verify/consume, attempt cap with lock) is delegated to
/// <see cref="IEmailOtpStore"/>.
/// </summary>
internal sealed class EmailOtpService : IEmailOtpService
{
    /// <summary>Upper bound on submitted code length before hashing — guards against oversized input.</summary>
    private const int MaxCodeInputLength = 64;

    private readonly EmailOtpOptions _options;
    private readonly IEmailOtpStore _store;
    private readonly IEmailOtpCodeGenerator _generator;
    private readonly IEmailOtpHasher _hasher;
    private readonly IEmailOtpSender _sender;
    private readonly IEmailOtpEmailNormalizer _normalizer;
    private readonly TimeProvider _clock;

    public EmailOtpService(
        IOptions<EmailOtpOptions> options,
        IEmailOtpStore store,
        IEmailOtpCodeGenerator generator,
        IEmailOtpHasher hasher,
        IEmailOtpSender sender,
        IEmailOtpEmailNormalizer normalizer,
        TimeProvider clock)
    {
        _options = options.Value;
        _store = store;
        _generator = generator;
        _hasher = hasher;
        _sender = sender;
        _normalizer = normalizer;
        _clock = clock;
    }

    public async Task<EmailOtpRequestResult> RequestAsync(
        string email, string purpose = EmailOtpPurposes.Login, CancellationToken cancellationToken = default)
    {
        email = _normalizer.Normalize(email);
        ValidateEmail(email);
        purpose = ValidatePurpose(purpose);

        var now = _clock.GetUtcNow();
        var code = _generator.Generate(_options.CodeLength);

        var challengeId = Guid.NewGuid();
        var pending = new EmailOtpPendingChallenge(
            id: challengeId,
            email: email,
            purpose: purpose,
            codeHash: _hasher.Hash(code),
            deliveryDeadline: now + _options.Expiry,
            createdAt: now);

        // Crash-safe issuance: persist as pending (non-verifiable), deliver, then activate. If we crash or
        // delivery fails before activation, the previous active code is untouched and no undelivered code is
        // ever verifiable. Abandoned pending rows expire and are removed by PurgeExpired.
        await _store.CreatePendingAsync(pending, cancellationToken);

        try
        {
            await _sender.SendAsync(email, code, purpose, cancellationToken);
        }
        catch
        {
            await _store.InvalidateAsync(challengeId, EmailOtpStoreInvalidationReason.DeliveryFailed, CancellationToken.None);
            throw;
        }

        // Delivery already succeeded — finalize activation independently of the request's cancellation token,
        // so a client disconnect in this window can't leave a delivered code stuck pending and unusable.
        // (The store's own database command timeouts still bound the operation.) The lifetime is passed so the
        // store stamps ExpiresAt from its own clock at activation time.
        var activated = await _store.ActivateAsync(challengeId, _options.Expiry, CancellationToken.None);
        return new EmailOtpRequestResult(email, purpose, activated.ExpiresAt);
    }

    public async Task<EmailOtpVerifyResult> VerifyAsync(
        string email, string code, string purpose = EmailOtpPurposes.Login, CancellationToken cancellationToken = default)
    {
        email = _normalizer.Normalize(email);
        ValidateEmail(email);
        purpose = ValidatePurpose(purpose);

        // Bound the input before hashing; an oversized/empty code is a non-match, not a real attempt.
        if (string.IsNullOrEmpty(code) || code.Length > MaxCodeInputLength)
            return EmailOtpVerifyResult.Fail(EmailOtpFailureReason.CodeMismatch, email, purpose);

        var hashed = _hasher.Hash(code);
        if (hashed is null || hashed.Length is 0 or > EmailOtpSchema.CodeHashColumnBytes)
            throw new InvalidOperationException(
                $"The configured IEmailOtpHasher returned an invalid hash; it must be non-null and " +
                $"1..{EmailOtpSchema.CodeHashColumnBytes} bytes.");

        // Own the bytes before the async store call: the hasher contract permits reusing its output buffer,
        // so without this copy a concurrent verify could overwrite this candidate's hash while it is held
        // across the await — comparing a wrong code against another request's hash.
        var candidateHash = (byte[])hashed.Clone();

        // The store reads the clock itself, immediately before each transition, to decide expiry.
        var result = await _store.VerifyAsync(email, purpose, candidateHash, _options.MaxAttempts, cancellationToken);

        return result.Outcome switch
        {
            EmailOtpStoreVerificationOutcome.Success =>
                EmailOtpVerifyResult.Success(email, purpose),
            EmailOtpStoreVerificationOutcome.Expired =>
                EmailOtpVerifyResult.Fail(EmailOtpFailureReason.Expired, email, purpose),
            EmailOtpStoreVerificationOutcome.MaxAttemptsExceeded =>
                EmailOtpVerifyResult.Fail(EmailOtpFailureReason.MaxAttemptsExceeded, email, purpose),
            EmailOtpStoreVerificationOutcome.CodeMismatch =>
                EmailOtpVerifyResult.Fail(
                    EmailOtpFailureReason.CodeMismatch, email, purpose,
                    Math.Max(0, _options.MaxAttempts - result.AttemptCount)),
            _ => EmailOtpVerifyResult.Fail(EmailOtpFailureReason.NotFound, email, purpose),
        };
    }

    private void ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            throw new ArgumentException("Not a valid email address.", nameof(email));
        if (email.Length > _options.MaxEmailLength)
            throw new ArgumentException($"Email exceeds the maximum length of {_options.MaxEmailLength}.", nameof(email));
    }

    private string ValidatePurpose(string purpose)
    {
        purpose = (purpose ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(purpose))
            throw new ArgumentException("purpose must not be empty.", nameof(purpose));
        if (purpose.Length > _options.MaxPurposeLength)
            throw new ArgumentException($"purpose exceeds the maximum length of {_options.MaxPurposeLength}.", nameof(purpose));
        return purpose;
    }
}
