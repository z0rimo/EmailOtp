using Microsoft.EntityFrameworkCore;

namespace EmailOtp.EntityFramework;

/// <summary>Extension for registering the EmailOtp mapping in a consumer DbContext's <c>OnModelCreating</c>.</summary>
public static class ModelBuilderExtensions
{
    /// <summary>
    /// Adds the EmailOtp challenge entity mapping (the <c>EmailOtpChallenges</c> table) to a consumer
    /// DbContext. The entity type itself is internal to this adapter — consumers only call this method.
    /// <code>
    /// protected override void OnModelCreating(ModelBuilder b) => b.AddEmailOtp();
    /// </code>
    /// </summary>
    public static ModelBuilder AddEmailOtp(
        this ModelBuilder modelBuilder, string? tableName = null, string? activeIndexFilter = null)
    {
        modelBuilder.ApplyConfiguration(new EmailOtpChallengeConfiguration(tableName, activeIndexFilter));
        return modelBuilder;
    }
}
