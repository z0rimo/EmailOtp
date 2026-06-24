using EmailOtp;
using EmailOtp.Tests.Fakes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace EmailOtp.Tests;

/// <summary>
/// Verifies the full AddEmailOtp(...).UseEntityFramework&lt;T&gt;().AddSender&lt;T&gt;() wiring and the
/// pepper fail-fast.
/// </summary>
public class DependencyInjectionTests
{
    private const string Pepper = "test-pepper-at-least-16-bytes-long!!";

    [Fact]
    public async Task Full_wiring_resolves_service_and_works_end_to_end()
    {
        using var conn = new SqliteConnection("DataSource=:memory:");
        conn.Open();

        var services = new ServiceCollection();
        services.AddDbContext<TestEmailOtpDbContext>(o => o.UseSqlite(conn));
        services.AddEmailOtp(o => o.Secret = Pepper)
            .UseEntityFramework<TestEmailOtpDbContext>()
            .AddSender<CapturingEmailOtpSender>();

        using var sp = services.BuildServiceProvider();

        using (var scope = sp.CreateScope())
            scope.ServiceProvider.GetRequiredService<TestEmailOtpDbContext>().Database.EnsureCreated();

        using (var scope = sp.CreateScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<IEmailOtpService>();
            var sender = (CapturingEmailOtpSender)scope.ServiceProvider.GetRequiredService<IEmailOtpSender>();

            await svc.RequestAsync("user@example.com");
            var result = await svc.VerifyAsync("user@example.com", sender.LastCode!);

            Assert.True(result.Succeeded);
        }
    }

    [Fact]
    public void Resolving_options_with_short_pepper_fails_fast()
    {
        var services = new ServiceCollection();
        services.AddEmailOtp(o => o.Secret = "tooshort");

        using var sp = services.BuildServiceProvider();

        var ex = Assert.Throws<OptionsValidationException>(
            () => sp.GetRequiredService<IOptions<EmailOtpOptions>>().Value);
        Assert.Contains("pepper", ex.Message);
    }

    [Fact]
    public void Resolving_options_with_valid_pepper_succeeds()
    {
        var services = new ServiceCollection();
        services.AddEmailOtp(o => o.Secret = Pepper);

        using var sp = services.BuildServiceProvider();

        var options = sp.GetRequiredService<IOptions<EmailOtpOptions>>().Value;
        Assert.Equal(Pepper, options.Secret);
    }
}
