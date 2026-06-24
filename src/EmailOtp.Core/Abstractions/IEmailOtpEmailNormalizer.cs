namespace EmailOtp;

/// <summary>
/// Normalizes an email before storage/lookup. This package is not an email-validation library; the
/// built-in default only trims and optionally lower-cases.
/// </summary>
public interface IEmailOtpEmailNormalizer
{
    string Normalize(string email);
}
