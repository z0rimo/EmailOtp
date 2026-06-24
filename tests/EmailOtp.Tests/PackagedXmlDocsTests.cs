using System.Xml.Linq;

namespace EmailOtp.Tests;

/// <summary>
/// Guards the shipped XML doc files against leaking internal implementation names.
/// The MSBuild strip task filters the XML at build time; these tests catch any filter
/// misconfiguration at test time (wrong namespace, missing entry, etc.).
/// </summary>
public class PackagedXmlDocsTests
{
    // Mirrors the @(EmailOtpInternalDocId) lists in the project files.
    // Any type/member listed here must NOT appear as a <member> entry in the shipped XML.
    private static readonly string[] InternalDocPrefixes =
    [
        "EmailOtp.EmailOtpService",
        "EmailOtp.HmacEmailOtpHasher",
        "EmailOtp.NumericEmailOtpCodeGenerator",
        "EmailOtp.DefaultEmailOtpEmailNormalizer",
        "Microsoft.Extensions.DependencyInjection.EmailOtpOptionsValidator",
        "EmailOtp.EmailOtpOptions.Validate",
        "EmailOtp.EmailOtpOptions.MinSecretBytes",
        "EmailOtp.EntityFramework.EfEmailOtpStore",
        "EmailOtp.EntityFramework.EmailOtpChallenge",
        "EmailOtp.EntityFramework.EmailOtpChallengeStatus",
        "EmailOtp.EntityFramework.EmailOtpChallengeConfiguration",
    ];

    [Theory]
    [InlineData("EmailOtp.Core.xml")]
    [InlineData("EmailOtp.EntityFramework.xml")]
    public void Packaged_xml_contains_no_internal_type_entries(string xmlFileName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, xmlFileName);
        Assert.True(File.Exists(path),
            $"{xmlFileName} not found in test output — run a full build before executing these tests.");

        var doc = XDocument.Load(path);
        var members = doc.Root?.Element("members");
        Assert.NotNull(members);

        var leaked = members!.Elements("member")
            .Select(m => (string?)m.Attribute("name") ?? "")
            .Where(IsInternalDocId)
            .ToList();

        Assert.True(leaked.Count == 0,
            $"{xmlFileName} still contains {leaked.Count} internal member doc entr(ies):\n  " +
            string.Join("\n  ", leaked));
    }

    private static bool IsInternalDocId(string docId)
    {
        int colon = docId.IndexOf(':');
        string id = colon >= 0 ? docId[(colon + 1)..] : docId;
        foreach (var pfx in InternalDocPrefixes)
        {
            if (id == pfx) return true;
            if (id.Length > pfx.Length && id.StartsWith(pfx, StringComparison.Ordinal))
            {
                char c = id[pfx.Length];
                if (c is '.' or '`' or '(') return true;
            }
        }
        return false;
    }
}
