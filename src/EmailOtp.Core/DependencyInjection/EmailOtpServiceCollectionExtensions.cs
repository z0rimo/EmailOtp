using EmailOtp;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers the EmailOtp Core services in DI.</summary>
public static class EmailOtpServiceCollectionExtensions
{
    /// <summary>
    /// Registers the issue/verify service and its defaults. Chain the store via an adapter
    /// (e.g. <c>.UseEntityFramework&lt;TContext&gt;()</c>) and the delivery via <c>.AddSender&lt;TSender&gt;()</c>.
    /// Invalid configuration (e.g. a missing/short pepper) fails at startup via <c>ValidateOnStart</c>.
    /// </summary>
    public static EmailOtpBuilder AddEmailOtp(
        this IServiceCollection services, Action<EmailOtpOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<EmailOtpOptions>()
            .Configure(configure)
            .ValidateOnStart();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<EmailOtpOptions>, EmailOtpOptionsValidator>());

        // Defaults are TryAdd so consumers can override any of them before/after this call.
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IEmailOtpCodeGenerator, NumericEmailOtpCodeGenerator>();
        services.TryAddSingleton<IEmailOtpHasher, HmacEmailOtpHasher>();
        services.TryAddSingleton<IEmailOtpEmailNormalizer, DefaultEmailOtpEmailNormalizer>();
        services.TryAddScoped<IEmailOtpService, EmailOtpService>();

        return new EmailOtpBuilder(services);
    }
}

/// <summary>Hooks <see cref="EmailOtpOptions.Validate"/> into the options validation pipeline.</summary>
internal sealed class EmailOtpOptionsValidator : IValidateOptions<EmailOtpOptions>
{
    public ValidateOptionsResult Validate(string? name, EmailOtpOptions options)
    {
        try
        {
            options.Validate();
            return ValidateOptionsResult.Success;
        }
        catch (Exception ex)
        {
            return ValidateOptionsResult.Fail(ex.Message);
        }
    }
}
