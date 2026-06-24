namespace EmailOtp;

/// <summary>
/// Persistence column sizes for the EmailOtp challenge table — the single source of truth shared by option
/// validation (so a validated input can never overflow its column) and the EF mapping. Public so consumers
/// writing a hand migration or a custom <see cref="IEmailOtpStore"/> can provision matching columns, and so
/// the EF adapter can reference them without friend access to Core internals.
/// </summary>
public static class EmailOtpSchema
{
    /// <summary>Email column size, in characters. RFC 5321 maximum.</summary>
    public const int EmailColumnLength = 320;

    /// <summary>Purpose column size, in characters.</summary>
    public const int PurposeColumnLength = 64;

    /// <summary>Code-hash column size, in bytes. HMAC-SHA256 is 32 bytes; a custom hasher must stay within this.</summary>
    public const int CodeHashColumnBytes = 64;
}
