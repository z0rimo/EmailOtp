namespace EmailOtp;

// ── Advanced store-implementer contracts ────────────────────────────────────────────────────────────────
// These types are the protocol between EmailOtpService and an IEmailOtpStore implementation. Most consumers
// never touch them — they are for writing a custom store (Dapper, Redis, …). The persistence model itself
// (the row, its status, the concurrency token) is owned privately by each adapter and is not exposed here.

/// <summary>
/// Immutable command for <see cref="IEmailOtpStore.CreatePendingAsync"/>: a not-yet-delivered code for an
/// (email, purpose) slot. <see cref="DeliveryDeadline"/> is the pre-activation deadline — the code must be
/// delivered and activated before it; the store stamps a fresh verification lifetime at activation time.
/// <para>
/// <b>Hash ownership:</b> the constructor defensively copies the supplied hash and the
/// <see cref="CodeHash"/> getter returns a fresh copy each read, so the hash bytes are owned solely by this
/// instance. A caller (or a custom <see cref="IEmailOtpHasher"/>) may safely reuse or retain its buffer, and a
/// store cannot corrupt the value by mutating what it reads. The hash must be non-null and
/// 1..<see cref="EmailOtpSchema.CodeHashColumnBytes"/> bytes (never the plaintext code).
/// </para>
/// </summary>
public sealed record EmailOtpPendingChallenge
{
    private readonly byte[] _codeHash;

    /// <summary>Creates the command, validating and defensively copying the code hash.</summary>
    public EmailOtpPendingChallenge(
        Guid id,
        string email,
        string purpose,
        byte[] codeHash,
        DateTimeOffset deliveryDeadline,
        DateTimeOffset createdAt)
    {
        ArgumentNullException.ThrowIfNull(codeHash);
        if (codeHash.Length is 0 or > EmailOtpSchema.CodeHashColumnBytes)
            throw new ArgumentException(
                $"Code hash must be 1..{EmailOtpSchema.CodeHashColumnBytes} bytes (got {codeHash.Length}). " +
                "A custom IEmailOtpHasher must return a non-empty, fixed-length hash within this bound.",
                nameof(codeHash));

        Id = id;
        Email = email;
        Purpose = purpose;
        _codeHash = (byte[])codeHash.Clone(); // defensive copy in — the caller may reuse/retain its buffer
        DeliveryDeadline = deliveryDeadline;
        CreatedAt = createdAt;
    }

    /// <summary>Challenge identity (the row's primary key).</summary>
    public Guid Id { get; }

    /// <summary>Normalized recipient email.</summary>
    public string Email { get; }

    /// <summary>The challenge purpose (e.g. <c>login</c>).</summary>
    public string Purpose { get; }

    /// <summary>The already-hashed code (never plaintext). Returns a fresh copy each read.</summary>
    public byte[] CodeHash => (byte[])_codeHash.Clone(); // defensive copy out — the stored bytes stay owned here

    /// <summary>Pre-activation deadline: the code must be delivered and activated before this instant.</summary>
    public DateTimeOffset DeliveryDeadline { get; }

    /// <summary>When the challenge was created.</summary>
    public DateTimeOffset CreatedAt { get; }
}

/// <summary>Result of <see cref="IEmailOtpStore.ActivateAsync"/> — the activated code's verification expiry.</summary>
public sealed record EmailOtpActivationResult(DateTimeOffset ExpiresAt);

/// <summary>Outcome of <see cref="IEmailOtpStore.VerifyAsync"/>.</summary>
public enum EmailOtpStoreVerificationOutcome
{
    Success = 0,
    NotFound = 1,
    Expired = 2,
    CodeMismatch = 3,
    MaxAttemptsExceeded = 4,
}

/// <summary>
/// Result of <see cref="IEmailOtpStore.VerifyAsync"/>. <see cref="AttemptCount"/> is the post-operation
/// failed-attempt count (used to compute remaining attempts on a mismatch).
/// </summary>
public sealed record EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome Outcome, int AttemptCount);

/// <summary>Why a challenge is being invalidated via <see cref="IEmailOtpStore.InvalidateAsync"/>.</summary>
public enum EmailOtpStoreInvalidationReason
{
    Superseded = 0,
    Expired = 1,
    DeliveryFailed = 2,
    Manual = 3,
}
