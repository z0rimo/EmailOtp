using Microsoft.Extensions.Options;

namespace EmailOtp;

/// <summary>
/// Default normalizer: trims, and lower-cases (invariant) when
/// <see cref="EmailOtpOptions.NormalizeEmailToLowerInvariant"/> is set. No structural email validation.
/// </summary>
internal sealed class DefaultEmailOtpEmailNormalizer : IEmailOtpEmailNormalizer
{
    private readonly bool _toLower;

    public DefaultEmailOtpEmailNormalizer(IOptions<EmailOtpOptions> options)
        => _toLower = options.Value.NormalizeEmailToLowerInvariant;

    public string Normalize(string email)
    {
        var trimmed = (email ?? string.Empty).Trim();
        return _toLower ? trimmed.ToLowerInvariant() : trimmed;
    }
}
