using System.Security.Cryptography;

namespace EmailOtp;

/// <summary>
/// Generates an N-digit numeric code using a cryptographic RNG (uniform per digit, no bias),
/// allowing leading zeros.
/// </summary>
internal sealed class NumericEmailOtpCodeGenerator : IEmailOtpCodeGenerator
{
    public string Generate(int length)
    {
        if (length < 1)
            throw new ArgumentOutOfRangeException(nameof(length), "Code length must be at least 1.");

        Span<char> chars = stackalloc char[length];
        for (var i = 0; i < length; i++)
            chars[i] = (char)('0' + RandomNumberGenerator.GetInt32(0, 10));

        return new string(chars);
    }
}
