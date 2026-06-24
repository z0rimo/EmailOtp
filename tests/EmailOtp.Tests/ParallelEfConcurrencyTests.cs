using EmailOtp;
using EmailOtp.EntityFramework;
using EmailOtp.Tests.Fakes;
using Microsoft.EntityFrameworkCore;

namespace EmailOtp.Tests;

/// <summary>
/// Genuinely parallel concurrency tests: many tasks hit the same challenge at once through separate
/// connections to a shared SQLite file (writes serialize via SQLite's busy timeout; logical conflicts are
/// resolved by the RowVersion token + retry). Asserts the hard invariants that must always hold —
/// no double-consume, and the attempt count never exceeds the cap.
/// </summary>
public class ParallelEfConcurrencyTests : IDisposable
{
    private static readonly byte[] CorrectHash = { 1, 2, 3, 4 };
    private static readonly byte[] WrongHash = { 9, 8, 7, 6 };
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly string _dbPath;

    public ParallelEfConcurrencyTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"emailotp-{Guid.NewGuid():N}.db");
        using var ctx = NewContext();
        ctx.Database.EnsureCreated();
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }

    private TestEmailOtpDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<TestEmailOtpDbContext>()
            .UseSqlite($"Data Source={_dbPath}")
            .Options;
        return new TestEmailOtpDbContext(options);
    }

    private EfEmailOtpStore<TestEmailOtpDbContext> NewStore(TestEmailOtpDbContext ctx)
        => new(ctx, new TestTimeProvider(T0));

    private async Task<Guid> SeedActiveAsync(string email)
    {
        var id = Guid.NewGuid();
        var deadline = T0 + TimeSpan.FromMinutes(10);
        await using var ctx = NewContext();
        var store = NewStore(ctx);
        await store.CreatePendingAsync(new EmailOtpPendingChallenge(id, email, EmailOtpPurposes.Login, CorrectHash, deadline, T0));
        await store.ActivateAsync(id, deadline - T0); // store clock is T0
        return id;
    }

    private async Task<EmailOtpStoreVerificationResult?> VerifyOnceAsync(string email, byte[] hash, int max)
    {
        await using var ctx = NewContext();
        try { return await NewStore(ctx).VerifyAsync(email, EmailOtpPurposes.Login, hash, max); }
        catch (EmailOtpConcurrencyException) { return null; } // documented transient
    }

    [Fact]
    public async Task Parallel_correct_verify_consumes_exactly_once()
    {
        var id = await SeedActiveAsync("race-consume@example.com");

        var results = await Task.WhenAll(Enumerable.Range(0, 24)
            .Select(_ => Task.Run(() => VerifyOnceAsync("race-consume@example.com", CorrectHash, 5))));

        Assert.Equal(0, results.Count(r => r is null)); // no transient concurrency failures expected
        var successes = results.Count(r => r?.Outcome == EmailOtpStoreVerificationOutcome.Success);
        Assert.Equal(1, successes); // exactly one consume — never zero, never double

        await using var verify = NewContext();
        var row = await verify.Set<EmailOtpChallenge>().AsNoTracking().SingleAsync(c => c.Id == id);
        Assert.Equal(EmailOtpChallengeStatus.Verified, row.Status);
    }

    [Fact]
    public async Task Parallel_wrong_verify_never_exceeds_cap()
    {
        const int max = 5;
        var id = await SeedActiveAsync("race-brute@example.com");

        var results = await Task.WhenAll(Enumerable.Range(0, 30)
            .Select(_ => Task.Run(() => VerifyOnceAsync("race-brute@example.com", WrongHash, max))));

        Assert.Equal(0, results.Count(r => r is null)); // no transient concurrency failures expected
        // No observed result ever reports a count beyond the cap.
        Assert.All(results.Where(r => r is not null), r => Assert.True(r!.AttemptCount <= max));

        await using var verify = NewContext();
        var row = await verify.Set<EmailOtpChallenge>().AsNoTracking().SingleAsync(c => c.Id == id);
        Assert.Equal(max, row.AttemptCount); // capped exactly, never exceeded
        Assert.Equal(EmailOtpChallengeStatus.Locked, row.Status);
    }
}
