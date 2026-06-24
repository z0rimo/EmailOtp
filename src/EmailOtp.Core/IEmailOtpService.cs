namespace EmailOtp;

/// <summary>
/// Entry point for EmailOtp. Responsible only for issuing and verifying email verification codes;
/// user lookup/creation and session issuance are the caller's job.
/// </summary>
public interface IEmailOtpService
{
    /// <summary>
    /// Issues a code for <paramref name="email"/> and delivers it. Any existing active challenge for the
    /// same (email, purpose) is superseded. If delivery fails, the new challenge is invalidated and the
    /// delivery exception propagates to the caller. Throws <see cref="ArgumentException"/> on invalid input.
    /// </summary>
    Task<EmailOtpRequestResult> RequestAsync(
        string email,
        string purpose = EmailOtpPurposes.Login,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies <paramref name="code"/>. Returns an <see cref="EmailOtpVerifyResult"/> rather than throwing.
    /// On success the code is consumed atomically and cannot be reused.
    /// </summary>
    Task<EmailOtpVerifyResult> VerifyAsync(
        string email,
        string code,
        string purpose = EmailOtpPurposes.Login,
        CancellationToken cancellationToken = default);
}
