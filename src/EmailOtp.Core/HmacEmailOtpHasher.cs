using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace EmailOtp;

/// <summary>
/// HMAC-SHA256 hasher keyed with a server-side pepper (32-byte output).
/// A 6-digit code has only one million possibilities, so a keyless SHA-256 is trivially reversed from a
/// database dump. The pepper (kept outside the database) is the HMAC key, blocking that reversal.
/// </summary>
internal sealed class HmacEmailOtpHasher : IEmailOtpHasher
{
    private readonly byte[] _pepper;

    public HmacEmailOtpHasher(IOptions<EmailOtpOptions> options)
    {
        var secret = options.Value.Secret;
        if (string.IsNullOrWhiteSpace(secret))
            throw new InvalidOperationException("HmacEmailOtpHasher: EmailOtpOptions.Secret (pepper) is not configured.");

        _pepper = Encoding.UTF8.GetBytes(secret);
    }

    public byte[] Hash(string code)
    {
        using var hmac = new HMACSHA256(_pepper);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(code)); // 32 bytes
    }
}
