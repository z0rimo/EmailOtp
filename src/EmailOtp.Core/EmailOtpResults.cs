namespace EmailOtp;

/// <summary>Result of issuing a code via <see cref="IEmailOtpService.RequestAsync"/>.</summary>
public sealed record EmailOtpRequestResult(
    string Email,
    string Purpose,
    DateTimeOffset ExpiresAt);

/// <summary>Why a verification failed.</summary>
public enum EmailOtpFailureReason
{
    /// <summary>No active challenge for the slot (never issued, already used, superseded, or locked).</summary>
    NotFound = 0,

    /// <summary>The active challenge is past its expiry.</summary>
    Expired = 1,

    /// <summary>The code did not match.</summary>
    CodeMismatch = 2,

    /// <summary>The attempt cap was reached; the challenge is now locked.</summary>
    MaxAttemptsExceeded = 3,
}

/// <summary>
/// Result of <see cref="IEmailOtpService.VerifyAsync"/>. Returned instead of throwing.
/// On success the caller has proof the user controls the inbox; user lookup/creation and session
/// issuance remain the application's responsibility. Keep <see cref="FailureReason"/> and
/// <see cref="RemainingAttempts"/> for logging/metrics — don't echo them to end users.
/// </summary>
public sealed record EmailOtpVerifyResult
{
    public bool Succeeded { get; init; }
    public EmailOtpFailureReason? FailureReason { get; init; }
    public int RemainingAttempts { get; init; }
    public string Email { get; init; } = string.Empty;
    public string Purpose { get; init; } = string.Empty;

    public static EmailOtpVerifyResult Success(string email, string purpose) =>
        new() { Succeeded = true, Email = email, Purpose = purpose };

    public static EmailOtpVerifyResult Fail(
        EmailOtpFailureReason reason, string email, string purpose, int remainingAttempts = 0) =>
        new()
        {
            Succeeded = false,
            FailureReason = reason,
            Email = email,
            Purpose = purpose,
            RemainingAttempts = remainingAttempts,
        };
}
