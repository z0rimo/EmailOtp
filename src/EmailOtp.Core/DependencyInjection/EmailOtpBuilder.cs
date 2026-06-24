using EmailOtp;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Result of <see cref="EmailOtpServiceCollectionExtensions.AddEmailOtp"/>. Chains the storage adapter
/// (e.g. <c>UseEntityFramework&lt;TContext&gt;()</c>) and the sender registration.
/// </summary>
public sealed class EmailOtpBuilder
{
    public IServiceCollection Services { get; }

    internal EmailOtpBuilder(IServiceCollection services) => Services = services;

    /// <summary>
    /// Registers the delivery implementation (<see cref="IEmailOtpSender"/>). Uses <c>AddScoped</c> so an
    /// explicit consumer registration overrides any earlier one.
    /// </summary>
    public EmailOtpBuilder AddSender<TSender>() where TSender : class, IEmailOtpSender
    {
        Services.AddScoped<IEmailOtpSender, TSender>();
        return this;
    }
}
