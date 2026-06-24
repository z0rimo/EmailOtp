using EmailOtp;
using EmailOtp.EntityFramework;
using EmailOtp.Tests.Fakes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace EmailOtp.Tests;

/// <summary>
/// EF adapter tests on real SQLite: slot isolation, the filtered unique index, the atomic verify
/// operation, invalidation, RowVersion rotation, and purge.
/// </summary>
public class EfEmailOtpStoreTests : IDisposable
{
    private const string Pepper = "test-pepper-at-least-16-bytes-long!!";
    private static readonly byte[] CorrectHash = { 1, 2, 3, 4 };
    private static readonly byte[] WrongHash = { 9, 8, 7, 6 };
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _conn;

    public EfEmailOtpStoreTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        using var ctx = NewContext();
        ctx.Database.EnsureCreated();
    }

    public void Dispose() => _conn.Dispose();

    private TestEmailOtpDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<TestEmailOtpDbContext>().UseSqlite(_conn).Options;
        return new TestEmailOtpDbContext(options);
    }

    private EfEmailOtpStore<TestEmailOtpDbContext> NewStore(TestEmailOtpDbContext ctx, DateTimeOffset? now = null)
        => new(ctx, new TestTimeProvider(now ?? T0));

    private EmailOtpService NewService(TestEmailOtpDbContext ctx, IEmailOtpSender sender, params string[] codes)
    {
        var options = Options.Create(new EmailOtpOptions { Secret = Pepper });
        return new EmailOtpService(
            options, NewStore(ctx), new SequenceEmailOtpCodeGenerator(codes),
            new HmacEmailOtpHasher(options), sender,
            new DefaultEmailOtpEmailNormalizer(options), new TestTimeProvider(T0));
    }

    // Seed an Active challenge through the store (create pending + activate), returning its id.
    private async Task<Guid> SeedActiveAsync(
        string email, string purpose = EmailOtpPurposes.Login, byte[]? codeHash = null, DateTimeOffset? expiresAt = null)
    {
        var id = Guid.NewGuid();
        var deadline = expiresAt ?? T0 + TimeSpan.FromMinutes(10);
        await using var ctx = NewContext();
        var store = NewStore(ctx);
        await store.CreatePendingAsync(new EmailOtpPendingChallenge(id, email, purpose, codeHash ?? CorrectHash, deadline, T0));
        await store.ActivateAsync(id, deadline - T0); // store clock is T0; preserves the intended expiry
        return id;
    }

    private async Task<EmailOtpChallenge> RowAsync(Guid id)
    {
        await using var ctx = NewContext();
        return await ctx.Set<EmailOtpChallenge>().AsNoTracking().SingleAsync(c => c.Id == id);
    }

    // A raw EF entity for direct-DB scenarios (unique-index, purge seeding).
    private static EmailOtpChallenge RawEntity(
        string email, DateTimeOffset expiresAt, EmailOtpChallengeStatus status, byte[]? codeHash = null)
        => new()
        {
            Id = Guid.NewGuid(),
            Email = email,
            Purpose = EmailOtpPurposes.Login,
            CodeHash = codeHash ?? CorrectHash,
            ExpiresAt = expiresAt,
            CreatedAt = T0.AddMinutes(-20),
            UpdatedAt = T0.AddMinutes(-20),
            Status = status,
            RowVersion = Guid.NewGuid().ToByteArray(),
        };

    // ── Slot isolation ────────────────────────────────────────────

    [Fact]
    public async Task Same_email_and_purpose_keeps_one_active()
    {
        await SeedActiveAsync("user@example.com");
        await SeedActiveAsync("user@example.com");
        await SeedActiveAsync("user@example.com");

        await using var verify = NewContext();
        var rows = await verify.Set<EmailOtpChallenge>().AsNoTracking().ToListAsync();
        Assert.Equal(3, rows.Count);
        Assert.Single(rows, r => r.Status == EmailOtpChallengeStatus.Active);
    }

    [Fact]
    public async Task Mixed_case_email_maps_to_one_normalized_slot()
    {
        await using (var ctx = NewContext())
            await NewService(ctx, new CapturingEmailOtpSender(), "111111").RequestAsync("USER@Example.COM");
        await using (var ctx = NewContext())
            await NewService(ctx, new CapturingEmailOtpSender(), "222222").RequestAsync("user@example.com");

        await using var verify = NewContext();
        var rows = await verify.Set<EmailOtpChallenge>().AsNoTracking().ToListAsync();
        Assert.Single(rows, r => r.Status == EmailOtpChallengeStatus.Active);
        Assert.All(rows, r => Assert.Equal("user@example.com", r.Email));
    }

    [Fact]
    public async Task Same_email_different_purpose_is_independent()
    {
        await SeedActiveAsync("user@example.com", "login");
        await SeedActiveAsync("user@example.com", "email-change");

        await using var verify = NewContext();
        var active = await verify.Set<EmailOtpChallenge>().AsNoTracking()
            .Where(c => c.Status == EmailOtpChallengeStatus.Active).ToListAsync();
        Assert.Equal(2, active.Count);
    }

    [Fact]
    public async Task Different_email_same_purpose_is_independent()
    {
        await SeedActiveAsync("a@example.com");
        await SeedActiveAsync("b@example.com");

        await using var verify = NewContext();
        var active = await verify.Set<EmailOtpChallenge>().AsNoTracking()
            .Where(c => c.Status == EmailOtpChallengeStatus.Active).ToListAsync();
        Assert.Equal(2, active.Count);
    }

    [Fact]
    public async Task Filtered_unique_index_rejects_two_active_rows_for_one_slot()
    {
        await SeedActiveAsync("dup@example.com");

        await using var ctx = NewContext();
        ctx.Set<EmailOtpChallenge>().Add(RawEntity("dup@example.com", T0.AddMinutes(10), EmailOtpChallengeStatus.Active));

        await Assert.ThrowsAsync<DbUpdateException>(() => ctx.SaveChangesAsync());
    }

    // ── Atomic verify ─────────────────────────────────────────────

    [Fact]
    public async Task Verify_correct_code_consumes_and_cannot_be_reused()
    {
        var id = await SeedActiveAsync("consume@example.com");

        await using var ctx1 = NewContext();
        var first = await NewStore(ctx1).VerifyAsync("consume@example.com", EmailOtpPurposes.Login, CorrectHash, 5);
        await using var ctx2 = NewContext();
        var second = await NewStore(ctx2).VerifyAsync("consume@example.com", EmailOtpPurposes.Login, CorrectHash, 5);

        Assert.Equal(EmailOtpStoreVerificationOutcome.Success, first.Outcome);
        Assert.Equal(EmailOtpStoreVerificationOutcome.NotFound, second.Outcome);
        Assert.Equal(EmailOtpChallengeStatus.Verified, (await RowAsync(id)).Status);
    }

    [Fact]
    public async Task Verify_wrong_code_counts_and_locks_at_cap()
    {
        const int max = 3;
        var id = await SeedActiveAsync("brute@example.com");

        EmailOtpStoreVerificationResult? last = null;
        for (var i = 0; i < max; i++)
        {
            await using var ctx = NewContext();
            last = await NewStore(ctx).VerifyAsync("brute@example.com", EmailOtpPurposes.Login, WrongHash, max);
        }

        Assert.Equal(EmailOtpStoreVerificationOutcome.MaxAttemptsExceeded, last!.Outcome);

        var row = await RowAsync(id);
        Assert.Equal(max, row.AttemptCount); // never exceeds max
        Assert.Equal(EmailOtpChallengeStatus.Locked, row.Status);

        // Correct code after lock still fails (no active challenge).
        await using var ctx2 = NewContext();
        var afterLock = await NewStore(ctx2).VerifyAsync("brute@example.com", EmailOtpPurposes.Login, CorrectHash, max);
        Assert.Equal(EmailOtpStoreVerificationOutcome.NotFound, afterLock.Outcome);
    }

    [Fact]
    public async Task Verify_expired_challenge_returns_expired()
    {
        var id = await SeedActiveAsync("exp@example.com", expiresAt: T0.AddMinutes(10));

        await using var ctx = NewContext();
        // The store's own clock is past expiry — even a correct hash must not be accepted.
        var result = await NewStore(ctx, T0.AddMinutes(11))
            .VerifyAsync("exp@example.com", EmailOtpPurposes.Login, CorrectHash, 5);

        Assert.Equal(EmailOtpStoreVerificationOutcome.Expired, result.Outcome);
        Assert.Equal(EmailOtpChallengeStatus.Expired, (await RowAsync(id)).Status);
    }

    [Fact]
    public async Task Activate_rejects_non_positive_lifetime()
    {
        var id = Guid.NewGuid();
        await using var ctx = NewContext();
        var store = NewStore(ctx);
        await store.CreatePendingAsync(
            new EmailOtpPendingChallenge(id, "zero-life@example.com", EmailOtpPurposes.Login, CorrectHash, T0.AddMinutes(10), T0));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => store.ActivateAsync(id, TimeSpan.Zero));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => store.ActivateAsync(id, TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public async Task Cancellation_after_delivery_still_activates_the_code()
    {
        // The sender cancels the request token during delivery (a client disconnect right after the code was
        // emailed). Activation must still complete so the delivered code isn't left stuck pending.
        using var cts = new CancellationTokenSource();
        await using var ctx = NewContext();
        var svc = NewService(ctx, new CancelOnSendEmailOtpSender(cts), "123456");

        var result = await svc.RequestAsync("cancel@example.com", cancellationToken: cts.Token);

        Assert.Equal("cancel@example.com", result.Email);
        await using var verify = NewContext();
        var row = await verify.Set<EmailOtpChallenge>().AsNoTracking().SingleAsync();
        Assert.Equal(EmailOtpChallengeStatus.Active, row.Status); // delivered code is usable, not stuck pending
    }

    // ── Invalidation ──────────────────────────────────────────────

    [Fact]
    public async Task Invalidate_active_moves_it_out_of_active()
    {
        var id = await SeedActiveAsync("inv@example.com");

        await using var ctx = NewContext();
        await NewStore(ctx).InvalidateAsync(id, EmailOtpStoreInvalidationReason.DeliveryFailed);

        Assert.Equal(EmailOtpChallengeStatus.DeliveryFailed, (await RowAsync(id)).Status);
    }

    [Fact]
    public async Task Invalidate_non_active_is_idempotent_noop()
    {
        var id = await SeedActiveAsync("inv2@example.com");
        // Verify (consume) → Verified, then invalidate must be a no-op and not throw.
        await using (var ctx = NewContext())
            await NewStore(ctx).VerifyAsync("inv2@example.com", EmailOtpPurposes.Login, CorrectHash, 5);

        await using var ctx2 = NewContext();
        var ex = await Record.ExceptionAsync(
            () => NewStore(ctx2).InvalidateAsync(id, EmailOtpStoreInvalidationReason.Manual));
        Assert.Null(ex);

        Assert.Equal(EmailOtpChallengeStatus.Verified, (await RowAsync(id)).Status); // unchanged
    }

    // ── Concurrency token ─────────────────────────────────────────

    [Fact]
    public async Task Store_rotates_rowversion_on_each_mutation()
    {
        var id = await SeedActiveAsync("rotate@example.com");
        var before = (await RowAsync(id)).RowVersion;

        await using (var ctx = NewContext())
            await NewStore(ctx).VerifyAsync("rotate@example.com", EmailOtpPurposes.Login, WrongHash, 5); // counts an attempt

        var after = (await RowAsync(id)).RowVersion;
        Assert.False(before.SequenceEqual(after));
    }

    [Fact]
    public async Task RowVersion_token_detects_stale_update()
    {
        var id = await SeedActiveAsync("token@example.com");

        await using var ctx1 = NewContext();
        await using var ctx2 = NewContext();
        var e1 = await ctx1.Set<EmailOtpChallenge>().FirstAsync(x => x.Id == id);
        var e2 = await ctx2.Set<EmailOtpChallenge>().FirstAsync(x => x.Id == id);

        e1.AttemptCount++;
        e1.RowVersion = Guid.NewGuid().ToByteArray();
        await ctx1.SaveChangesAsync();

        e2.AttemptCount++;
        e2.RowVersion = Guid.NewGuid().ToByteArray();
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => ctx2.SaveChangesAsync());
    }

    // ── Purge ─────────────────────────────────────────────────────

    [Fact]
    public async Task Purge_removes_every_row_past_expiry_regardless_of_status()
    {
        await AddRawAsync("expired-super@example.com", T0.AddMinutes(-5), EmailOtpChallengeStatus.Superseded);
        await AddRawAsync("expired-active@example.com", T0.AddMinutes(-1), EmailOtpChallengeStatus.Active);
        await AddRawAsync("fresh-verified@example.com", T0.AddMinutes(10), EmailOtpChallengeStatus.Verified);
        await SeedActiveAsync("fresh-active@example.com");

        await using var purgeCtx = NewContext();
        var removed = await NewStore(purgeCtx).PurgeExpiredAsync(T0);

        Assert.Equal(2, removed);
        await using var verify = NewContext();
        var remaining = await verify.Set<EmailOtpChallenge>().AsNoTracking().Select(c => c.Email).ToListAsync();
        Assert.Equal(2, remaining.Count);
        Assert.Contains("fresh-verified@example.com", remaining);
        Assert.Contains("fresh-active@example.com", remaining);
    }

    private async Task AddRawAsync(string email, DateTimeOffset expiresAt, EmailOtpChallengeStatus status)
    {
        await using var ctx = NewContext();
        ctx.Set<EmailOtpChallenge>().Add(RawEntity(email, expiresAt, status));
        await ctx.SaveChangesAsync();
    }
}
