using EmailOtp;
using EmailOtp.EntityFramework;
using EmailOtp.Tests.Fakes;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace EmailOtp.Tests;

/// <summary>
/// Deterministic two-context concurrency tests using a barrier interceptor that forces both racing
/// operations to read the same row version before either writes — so the CAS reload/retry path is actually
/// exercised — plus the pending-delivery lifecycle paths (not-verifiable, abandoned, sequential last-wins
/// activation, and expired-then-activated). Uses a shared SQLite file so each context has its own connection.
/// </summary>
public class DeterministicConcurrencyTests : IDisposable
{
    private static readonly byte[] CorrectHash = { 1, 2, 3, 4 };
    private static readonly byte[] WrongHash = { 9, 8, 7, 6 };
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly string _dbPath;

    public DeterministicConcurrencyTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"emailotp-det-{Guid.NewGuid():N}.db");
        using var ctx = NewContext();
        ctx.Database.EnsureCreated();
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }

    private TestEmailOtpDbContext NewContext(IInterceptor? interceptor = null)
    {
        var builder = new DbContextOptionsBuilder<TestEmailOtpDbContext>().UseSqlite($"Data Source={_dbPath}");
        if (interceptor is not null) builder.AddInterceptors(interceptor);
        return new TestEmailOtpDbContext(builder.Options);
    }

    private EfEmailOtpStore<TestEmailOtpDbContext> NewStore(TestEmailOtpDbContext ctx, DateTimeOffset? now = null)
        => new(ctx, new TestTimeProvider(now ?? T0));

    private static EmailOtpPendingChallenge NewChallenge(
        string email, byte[]? codeHash = null, DateTimeOffset? deadline = null)
        => new(Guid.NewGuid(), email, EmailOtpPurposes.Login,
            codeHash ?? CorrectHash, deadline ?? T0 + TimeSpan.FromMinutes(10), T0);

    private async Task<Guid> SeedActiveAsync(string email, byte[]? codeHash = null)
    {
        var c = NewChallenge(email, codeHash);
        await using var ctx = NewContext();
        var store = NewStore(ctx);
        await store.CreatePendingAsync(c);
        await store.ActivateAsync(c.Id, c.DeliveryDeadline - T0); // store clock is T0
        return c.Id;
    }

    private async Task<EmailOtpChallenge> RowAsync(Guid id)
    {
        await using var ctx = NewContext();
        return await ctx.Set<EmailOtpChallenge>().AsNoTracking().SingleAsync(c => c.Id == id);
    }

    // ── Forced CAS conflicts (barrier) ────────────────────────────

    [Fact]
    public async Task Forced_conflict_two_wrong_verifies_are_both_counted()
    {
        var id = await SeedActiveAsync("race-attempt@example.com");
        var barrier = new Barrier(2);

        async Task<EmailOtpStoreVerificationResult> Wrong()
        {
            await using var ctx = NewContext(new FirstReadBarrierInterceptor(barrier));
            return await NewStore(ctx).VerifyAsync("race-attempt@example.com", EmailOtpPurposes.Login, WrongHash, 10);
        }

        var results = await Task.WhenAll(Task.Run(Wrong), Task.Run(Wrong));

        // Both load the same version; one wins, the other reloads (CAS) and also counts. Neither is lost.
        Assert.All(results, r => Assert.Equal(EmailOtpStoreVerificationOutcome.CodeMismatch, r.Outcome));
        var row = await RowAsync(id);
        Assert.Equal(2, row.AttemptCount);
    }

    [Fact]
    public async Task Forced_invalidation_versus_failed_attempt_ends_terminal_without_loss()
    {
        var id = await SeedActiveAsync("race-invalidate@example.com");
        var barrier = new Barrier(2);

        async Task Invalidate()
        {
            await using var ctx = NewContext(new FirstReadBarrierInterceptor(barrier));
            await NewStore(ctx).InvalidateAsync(id, EmailOtpStoreInvalidationReason.Manual);
        }

        async Task Attempt()
        {
            await using var ctx = NewContext(new FirstReadBarrierInterceptor(barrier));
            await NewStore(ctx).VerifyAsync("race-invalidate@example.com", EmailOtpPurposes.Login, WrongHash, 10);
        }

        // Whoever loses the race reloads and completes; invalidation never silently no-ops on a stale read.
        await Task.WhenAll(Task.Run(Invalidate), Task.Run(Attempt));

        var row = await RowAsync(id);
        Assert.Equal(EmailOtpChallengeStatus.Revoked, row.Status); // invalidation always lands
    }

    // ── Pending-delivery lifecycle ────────────────────────────────

    [Fact]
    public async Task Pending_challenge_is_not_verifiable()
    {
        var c = NewChallenge("pending@example.com");
        await using (var ctx = NewContext())
            await NewStore(ctx).CreatePendingAsync(c); // created but never activated

        await using var verifyCtx = NewContext();
        var result = await NewStore(verifyCtx)
            .VerifyAsync("pending@example.com", EmailOtpPurposes.Login, CorrectHash, 5);

        Assert.Equal(EmailOtpStoreVerificationOutcome.NotFound, result.Outcome);
    }

    [Fact]
    public async Task Abandoned_pending_is_removed_by_purge()
    {
        var c = NewChallenge("abandoned@example.com", deadline: T0.AddMinutes(-1)); // pending past its TTL
        await using (var ctx = NewContext())
            await NewStore(ctx).CreatePendingAsync(c);

        await using var purgeCtx = NewContext();
        var removed = await NewStore(purgeCtx).PurgeExpiredAsync(T0);

        Assert.Equal(1, removed);
        await using var verify = NewContext();
        Assert.False(await verify.Set<EmailOtpChallenge>().AnyAsync());
    }

    [Fact]
    public async Task Forced_conflict_two_correct_verifies_exactly_one_succeeds()
    {
        var id = await SeedActiveAsync("race-correct@example.com");
        var barrier = new Barrier(2);

        async Task<EmailOtpStoreVerificationResult> Correct()
        {
            await using var ctx = NewContext(new FirstReadBarrierInterceptor(barrier));
            return await NewStore(ctx).VerifyAsync("race-correct@example.com", EmailOtpPurposes.Login, CorrectHash, 5);
        }

        var results = await Task.WhenAll(Task.Run(Correct), Task.Run(Correct));

        // Both read the same active row; one consumes, the other reloads (CAS) and finds it gone.
        Assert.Equal(1, results.Count(r => r.Outcome == EmailOtpStoreVerificationOutcome.Success));
        Assert.Equal(1, results.Count(r => r.Outcome == EmailOtpStoreVerificationOutcome.NotFound));

        var row = await RowAsync(id);
        Assert.Equal(EmailOtpChallengeStatus.Verified, row.Status);
    }

    [Fact]
    public async Task Two_pending_activations_resolve_to_one_active_last_wins()
    {
        // Two pending challenges for the same slot, activated sequentially: the second supersedes the first.
        var p1 = NewChallenge("simul@example.com");
        var p2 = NewChallenge("simul@example.com");
        await using (var ctx = NewContext())
        {
            var store = NewStore(ctx);
            await store.CreatePendingAsync(p1);
            await store.CreatePendingAsync(p2);
        }

        await using (var ctx = NewContext())
            await NewStore(ctx).ActivateAsync(p1.Id, TimeSpan.FromMinutes(10));
        await using (var ctx = NewContext())
            await NewStore(ctx).ActivateAsync(p2.Id, TimeSpan.FromMinutes(10));

        await using var verify = NewContext();
        var rows = await verify.Set<EmailOtpChallenge>().AsNoTracking().ToListAsync();
        var active = Assert.Single(rows, c => c.Status == EmailOtpChallengeStatus.Active);
        Assert.Equal(p2.Id, active.Id); // last activation wins
        Assert.Equal(EmailOtpChallengeStatus.Superseded, rows.Single(c => c.Id == p1.Id).Status);
    }

    [Fact]
    public async Task Concurrent_overlapping_activation_resolves_to_one_active_without_deadlock()
    {
        // Repeated rounds of genuinely parallel same-slot activation (separate connections, file SQLite). With
        // BEGIN IMMEDIATE the two activations serialize at BEGIN — no deadlock — and each round must leave the
        // slot with exactly one active code (the other superseded). The repetition is the stress coverage.
        const int rounds = 8;
        for (var round = 0; round < rounds; round++)
        {
            var email = $"overlap{round}@example.com";
            var p1 = NewChallenge(email);
            var p2 = NewChallenge(email);
            await using (var ctx = NewContext())
            {
                var store = NewStore(ctx);
                await store.CreatePendingAsync(p1);
                await store.CreatePendingAsync(p2);
            }

            // Start gate: both tasks block here until released together, so they reach transaction acquisition
            // (the first thing ActivateAsync does) concurrently — deterministic overlap, not luck of scheduling.
            var gate = new Barrier(2);
            Task Activate(Guid id) => Task.Run(async () =>
            {
                await using var ctx = NewContext();
                var store = NewStore(ctx);
                gate.SignalAndWait();
                await store.ActivateAsync(id, TimeSpan.FromMinutes(10));
            });

            var ex = await Record.ExceptionAsync(() => Task.WhenAll(Activate(p1.Id), Activate(p2.Id)));
            Assert.Null(ex); // no deadlock, no unhandled exception

            await using var verify = NewContext();
            var slot = await verify.Set<EmailOtpChallenge>().AsNoTracking()
                .Where(c => c.Email == email).ToListAsync();
            Assert.Equal(1, slot.Count(c => c.Status == EmailOtpChallengeStatus.Active));     // exactly one active
            Assert.Equal(1, slot.Count(c => c.Status == EmailOtpChallengeStatus.Superseded)); // the other superseded
        }
    }

    [Fact]
    public async Task Failed_activation_rolls_back_and_preserves_the_existing_active()
    {
        // A valid active code B, and a new pending A. Every save during A's activation fails (simulated
        // transient lock). After the bounded retries are exhausted, activation throws — and the transaction
        // rollback must have preserved B (never a slot left with no active code) and left A still pending.
        var bId = await SeedActiveAsync("preserve@example.com");
        var a = NewChallenge("preserve@example.com");
        await using (var ctx = NewContext())
            await NewStore(ctx).CreatePendingAsync(a);

        await using var failCtx = NewContext(new ThrowTransientOnSaveInterceptor());
        var store = new EfEmailOtpStore<TestEmailOtpDbContext>(failCtx, new TestTimeProvider(T0));

        await Assert.ThrowsAsync<EmailOtpConcurrencyException>(
            () => store.ActivateAsync(a.Id, TimeSpan.FromMinutes(10)));

        Assert.Equal(EmailOtpChallengeStatus.Active, (await RowAsync(bId)).Status);            // B preserved
        Assert.Equal(EmailOtpChallengeStatus.PendingDelivery, (await RowAsync(a.Id)).Status);  // A still pending
    }

    [Fact]
    public async Task Expired_pending_is_rejected_and_does_not_supersede_newer_active()
    {
        // Older request A: pending created at T0 with a delivery deadline of T0+10.
        var a = NewChallenge("slow@example.com", codeHash: WrongHash, deadline: T0.AddMinutes(10));
        await using (var ctx = NewContext())
            await NewStore(ctx).CreatePendingAsync(a);

        // Newer request B issued and activated at T0+5 → active, valid until T0+15.
        var b = NewChallenge("slow@example.com", codeHash: CorrectHash);
        await using (var ctx = NewContext())
        {
            var store = NewStore(ctx, T0.AddMinutes(5));
            await store.CreatePendingAsync(b);
            await store.ActivateAsync(b.Id, TimeSpan.FromMinutes(10));
        }

        // A's slow delivery finishes at T0+11 — past A's delivery deadline. Activation must be rejected and
        // must NOT supersede B.
        await using (var ctx = NewContext())
            await Assert.ThrowsAsync<EmailOtpConcurrencyException>(
                () => NewStore(ctx, T0.AddMinutes(11)).ActivateAsync(a.Id, TimeSpan.FromMinutes(10)));

        Assert.Equal(EmailOtpChallengeStatus.Expired, (await RowAsync(a.Id)).Status);   // A expired, not activated
        Assert.Equal(EmailOtpChallengeStatus.Active, (await RowAsync(b.Id)).Status);    // B untouched, still active

        // B's code still verifies at T0+11 (B is valid until T0+15).
        await using var verifyCtx = NewContext();
        var result = await NewStore(verifyCtx, T0.AddMinutes(11))
            .VerifyAsync("slow@example.com", EmailOtpPurposes.Login, CorrectHash, 5);
        Assert.Equal(EmailOtpStoreVerificationOutcome.Success, result.Outcome);
    }

    [Fact]
    public async Task Activation_rechecks_deadline_between_initial_read_and_write()
    {
        // Pending created at T0 with a delivery deadline of T0+10. At the initial read the clock is T0
        // (unexpired); an interceptor advances it past the deadline before the transition writes.
        var a = NewChallenge("recheck@example.com", deadline: T0.AddMinutes(10));
        await using (var ctx = NewContext())
            await NewStore(ctx).CreatePendingAsync(a);

        var clock = new TestTimeProvider(T0);
        await using var actCtx = NewContext(new AdvanceClockOnFirstReadInterceptor(clock, TimeSpan.FromMinutes(11)));
        var store = new EfEmailOtpStore<TestEmailOtpDbContext>(actCtx, clock);

        // The deadline is rechecked at the write-time clock (T0+11), so activation is rejected.
        await Assert.ThrowsAsync<EmailOtpConcurrencyException>(
            () => store.ActivateAsync(a.Id, TimeSpan.FromMinutes(10)));
        Assert.Equal(EmailOtpChallengeStatus.Expired, (await RowAsync(a.Id)).Status);
    }

    [Fact]
    public async Task Verify_returns_expired_when_clock_crosses_expiry_during_cas_retry()
    {
        // Active code valid until T0+10. The first verify attempt reads at T0 (unexpired) and tries to count a
        // wrong attempt; an interceptor forces a CAS conflict on that save and advances the clock past expiry.
        // The retry re-reads and must return Expired (expiry re-evaluated from the store clock per attempt).
        var id = await SeedActiveAsync("retry-expiry@example.com");

        var clock = new TestTimeProvider(T0);
        await using var ctx = NewContext(new ConflictAndAdvanceOnFirstSaveInterceptor(
            () => NewContext(), id, clock, TimeSpan.FromMinutes(11)));
        var store = new EfEmailOtpStore<TestEmailOtpDbContext>(ctx, clock);

        var result = await store.VerifyAsync("retry-expiry@example.com", EmailOtpPurposes.Login, WrongHash, 5);

        Assert.Equal(EmailOtpStoreVerificationOutcome.Expired, result.Outcome);
    }
}
