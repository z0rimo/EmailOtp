using EmailOtp;
using EmailOtp.EntityFramework;
using Microsoft.EntityFrameworkCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Wires EmailOtp's store to EF Core.</summary>
public static class EmailOtpBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="IEmailOtpStore"/> backed by EF Core. <typeparamref name="TContext"/> must be a
    /// consumer DbContext that registered the EmailOtp mapping via <c>AddEmailOtp()</c> in
    /// <c>OnModelCreating</c>.
    /// </summary>
    public static EmailOtpBuilder UseEntityFramework<TContext>(this EmailOtpBuilder builder)
        where TContext : DbContext
    {
        builder.Services.AddScoped<IEmailOtpStore, EfEmailOtpStore<TContext>>();
        return builder;
    }
}
