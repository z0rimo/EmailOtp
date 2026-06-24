namespace EmailOtp;

/// <summary>Generates the plaintext code. The built-in default generates a numeric code.</summary>
public interface IEmailOtpCodeGenerator
{
    /// <summary>Generates a code of the given <paramref name="length"/> (leading zeros allowed).</summary>
    string Generate(int length);
}
