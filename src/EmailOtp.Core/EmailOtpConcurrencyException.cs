namespace EmailOtp;

/// <summary>
/// Thrown when a concurrency conflict could not be resolved within the retry budget. Callers should
/// treat it as a transient failure and prompt the user to retry.
/// </summary>
public sealed class EmailOtpConcurrencyException : Exception
{
    public EmailOtpConcurrencyException(string message) : base(message) { }
}
