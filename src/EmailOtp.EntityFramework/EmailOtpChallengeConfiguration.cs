using EmailOtp;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace EmailOtp.EntityFramework;

/// <summary>
/// Maps <see cref="EmailOtpChallenge"/>. Key points:
/// <list type="bullet">
///   <item>a <b>filtered unique index</b> on (Email, Purpose) WHERE Status = Active enforces a single
///         active challenge per slot at the database level;</item>
///   <item><see cref="EmailOtpChallenge.RowVersion"/> is an optimistic-concurrency token (rotated by the
///         store) so consume/attempt updates are compare-and-set on any provider, including SQLite;</item>
///   <item>DateTimeOffset is stored as UtcTicks(long) so comparisons translate across providers.</item>
/// </list>
/// </summary>
internal sealed class EmailOtpChallengeConfiguration : IEntityTypeConfiguration<EmailOtpChallenge>
{
    internal const string DefaultTableName = "EmailOtpChallenges";

    /// <summary>Default active-slot index filter. Works on SQLite and SQL Server; override for others.</summary>
    internal static readonly string DefaultActiveIndexFilter = $"[Status] = {(int)EmailOtpChallengeStatus.Active}";

    private readonly string _tableName;
    private readonly string _activeIndexFilter;

    public EmailOtpChallengeConfiguration(string? tableName = null, string? activeIndexFilter = null)
    {
        _tableName = tableName ?? DefaultTableName;
        _activeIndexFilter = activeIndexFilter ?? DefaultActiveIndexFilter;
    }

    public void Configure(EntityTypeBuilder<EmailOtpChallenge> builder)
    {
        builder.ToTable(_tableName);
        builder.HasKey(x => x.Id);

        builder.Property(x => x.Email).IsRequired().HasMaxLength(EmailOtpSchema.EmailColumnLength);
        builder.Property(x => x.Purpose).IsRequired().HasMaxLength(EmailOtpSchema.PurposeColumnLength);
        builder.Property(x => x.CodeHash).IsRequired().HasMaxLength(EmailOtpSchema.CodeHashColumnBytes);
        builder.Property(x => x.Status).IsRequired();
        builder.Property(x => x.AttemptCount).IsRequired();

        var toTicks = new ValueConverter<DateTimeOffset, long>(
            v => v.UtcTicks,
            v => new DateTimeOffset(v, TimeSpan.Zero));

        builder.Property(x => x.ExpiresAt).IsRequired().HasConversion(toTicks);
        builder.Property(x => x.CreatedAt).IsRequired().HasConversion(toTicks);
        builder.Property(x => x.UpdatedAt).IsRequired().HasConversion(toTicks);

        // Manually rotated optimistic-concurrency token (provider-general, works on SQLite).
        builder.Property(x => x.RowVersion).IsRequired().IsConcurrencyToken();

        // At most one Active challenge per (Email, Purpose), enforced by a partial/filtered unique index.
        // The default [Status] bracket-quoting is accepted by both SQLite and SQL Server; providers without
        // filtered-index support (or different quoting, e.g. PostgreSQL) pass a custom filter — see docs.
        builder.HasIndex(x => new { x.Email, x.Purpose })
            .IsUnique()
            .HasFilter(_activeIndexFilter);

        // Lookup helper for non-active history / purge scans.
        builder.HasIndex(x => x.ExpiresAt);
    }
}
