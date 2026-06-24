namespace EmailOtp;

/// <summary>
/// Delivers a generated code to the user (email, SMS, …). The package does not ship a default; the
/// consumer provides one. If delivery throws, the service invalidates the challenge so an unreceived
/// code is never left active.
/// </summary>
public interface IEmailOtpSender
{
    /// <summary>
    /// Delivers the plaintext <paramref name="code"/> to <paramref name="email"/>. The package itself never
    /// persists the plaintext code (only its HMAC). Your implementation must likewise avoid writing it to
    /// logs, queues, or third-party services unless those sinks are intentionally secured.
    /// </summary>
    Task SendAsync(string email, string code, string purpose, CancellationToken cancellationToken = default);
}
