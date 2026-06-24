using System.Text;

namespace EmailOtp;

/// <summary>
/// Configuration for EmailOtp. Configured through <c>AddEmailOtp(...)</c> in DI.
/// </summary>
public sealed class EmailOtpOptions
{
    /// <summary>Number of digits in a generated code. Default 6.</summary>
    public int CodeLength { get; set; } = 6;

    /// <summary>Code lifetime. Default 10 minutes.</summary>
    public TimeSpan Expiry { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Maximum verification attempts per challenge before it is locked. Default 5.</summary>
    public int MaxAttempts { get; set; } = 5;

    /// <summary>
    /// Server-side secret (pepper) used for HMAC hashing. Inject from an environment variable or a
    /// secret store, never from the database, and never store it alongside the code hashes.
    /// </summary>
    public string Secret { get; set; } = string.Empty;

    /// <summary>Lower-cases the email during normalization. Default true.</summary>
    public bool NormalizeEmailToLowerInvariant { get; set; } = true;

    /// <summary>Maximum accepted email length. Default 320 (RFC 5321).</summary>
    public int MaxEmailLength { get; set; } = 320;

    /// <summary>Maximum accepted purpose length. Default 64.</summary>
    public int MaxPurposeLength { get; set; } = 64;

    /// <summary>Minimum pepper length in bytes. Anything shorter is a configuration error.</summary>
    internal const int MinSecretBytes = 16;

    /// <summary>Validates the configuration. Throws immediately on invalid settings (startup fail-fast).</summary>
    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Secret) || Encoding.UTF8.GetByteCount(Secret) < MinSecretBytes)
            throw new InvalidOperationException(
                $"EmailOtpOptions.Secret (pepper) must be at least {MinSecretBytes} bytes. " +
                "Inject a sufficiently long random value, e.g. via an environment variable.");

        if (CodeLength is < 4 or > 12)
            throw new InvalidOperationException("EmailOtpOptions.CodeLength must be between 4 and 12.");

        if (MaxAttempts < 1)
            throw new InvalidOperationException("EmailOtpOptions.MaxAttempts must be at least 1.");

        if (Expiry <= TimeSpan.Zero)
            throw new InvalidOperationException("EmailOtpOptions.Expiry must be greater than zero.");

        if (MaxEmailLength is < 3 or > EmailOtpSchema.EmailColumnLength)
            throw new InvalidOperationException($"EmailOtpOptions.MaxEmailLength must be between 3 and {EmailOtpSchema.EmailColumnLength}.");

        if (MaxPurposeLength is < 1 or > EmailOtpSchema.PurposeColumnLength)
            throw new InvalidOperationException($"EmailOtpOptions.MaxPurposeLength must be between 1 and {EmailOtpSchema.PurposeColumnLength}.");
    }
}

/// <summary>Common OTP purpose constants. Consumers may use any string they like.</summary>
public static class EmailOtpPurposes
{
    public const string Login = "login";
}
