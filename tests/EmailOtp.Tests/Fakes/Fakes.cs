using System.Data.Common;
using EmailOtp;
using EmailOtp.EntityFramework;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace EmailOtp.Tests.Fakes;

/// <summary>
/// Blocks on a shared <see cref="Barrier"/> after the first read command on each context, so two racing
/// operations both load the same committed row version before either writes — deterministically forcing the
/// optimistic-concurrency conflict (and the store's reload/retry path). Subsequent reads (retries) pass
/// straight through.
/// </summary>
public sealed class FirstReadBarrierInterceptor : DbCommandInterceptor
{
    private readonly Barrier _barrier;
    private int _tripped;

    public FirstReadBarrierInterceptor(Barrier barrier) => _barrier = barrier;

    public override DbDataReader ReaderExecuted(
        DbCommand command, CommandExecutedEventData eventData, DbDataReader result)
    {
        TripOnce();
        return result;
    }

    public override ValueTask<DbDataReader> ReaderExecutedAsync(
        DbCommand command, CommandExecutedEventData eventData, DbDataReader result,
        CancellationToken cancellationToken = default)
    {
        TripOnce();
        return new ValueTask<DbDataReader>(result);
    }

    private void TripOnce()
    {
        if (Interlocked.Exchange(ref _tripped, 1) == 0)
            _barrier.SignalAndWait();
    }
}

/// <summary>Deterministic code generator — returns codes from a fixed sequence, ignoring length.</summary>
public sealed class SequenceEmailOtpCodeGenerator : IEmailOtpCodeGenerator
{
    private readonly Queue<string> _codes;

    public SequenceEmailOtpCodeGenerator(params string[] codes) => _codes = new Queue<string>(codes);

    public string Generate(int length)
    {
        if (_codes.Count == 0)
            throw new InvalidOperationException("SequenceEmailOtpCodeGenerator ran out of codes.");
        return _codes.Dequeue();
    }
}

/// <summary>Captures the plaintext code that was 'sent'.</summary>
public sealed class CapturingEmailOtpSender : IEmailOtpSender
{
    public string? LastCode { get; private set; }
    public string? LastEmail { get; private set; }
    public string? LastPurpose { get; private set; }
    public int SendCount { get; private set; }

    public Task SendAsync(string email, string code, string purpose, CancellationToken cancellationToken = default)
    {
        LastEmail = email;
        LastCode = code;
        LastPurpose = purpose;
        SendCount++;
        return Task.CompletedTask;
    }
}

/// <summary>Sender that always fails, to exercise the delivery-failure path.</summary>
public sealed class ThrowingEmailOtpSender : IEmailOtpSender
{
    public sealed class DeliveryException : Exception
    {
        public DeliveryException() : base("simulated delivery failure") { }
    }

    public Task SendAsync(string email, string code, string purpose, CancellationToken cancellationToken = default)
        => throw new DeliveryException();
}

/// <summary>Fails the first N sends, then captures like <see cref="CapturingEmailOtpSender"/>.</summary>
public sealed class FailThenCaptureEmailOtpSender : IEmailOtpSender
{
    private int _failuresRemaining;

    public FailThenCaptureEmailOtpSender(int failures) => _failuresRemaining = failures;

    public string? LastCode { get; private set; }

    public Task SendAsync(string email, string code, string purpose, CancellationToken cancellationToken = default)
    {
        if (_failuresRemaining > 0)
        {
            _failuresRemaining--;
            throw new ThrowingEmailOtpSender.DeliveryException();
        }
        LastCode = code;
        return Task.CompletedTask;
    }
}

/// <summary>Captures the code and cancels the supplied token during delivery (post-delivery cancellation test).</summary>
public sealed class CancelOnSendEmailOtpSender : IEmailOtpSender
{
    private readonly CancellationTokenSource _cts;

    public CancelOnSendEmailOtpSender(CancellationTokenSource cts) => _cts = cts;

    public string? LastCode { get; private set; }

    public Task SendAsync(string email, string code, string purpose, CancellationToken cancellationToken = default)
    {
        LastCode = code;
        _cts.Cancel(); // simulate a client disconnect right after the code was delivered
        return Task.CompletedTask;
    }
}

/// <summary>Wraps a hasher and counts how many times <see cref="Hash"/> is invoked.</summary>
public sealed class SpyEmailOtpHasher : IEmailOtpHasher
{
    private readonly IEmailOtpHasher _inner;

    public SpyEmailOtpHasher(IEmailOtpHasher inner) => _inner = inner;

    public int HashCallCount { get; private set; }

    public byte[] Hash(string code)
    {
        HashCallCount++;
        return _inner.Hash(code);
    }
}

/// <summary>Runs an async callback during the send (to interleave another request), then throws.</summary>
public sealed class CallbackThenThrowEmailOtpSender : IEmailOtpSender
{
    private readonly Func<Task> _onSend;

    public CallbackThenThrowEmailOtpSender(Func<Task> onSend) => _onSend = onSend;

    public async Task SendAsync(string email, string code, string purpose, CancellationToken cancellationToken = default)
    {
        await _onSend();
        throw new ThrowingEmailOtpSender.DeliveryException();
    }
}

/// <summary>Controllable clock for expiry tests.</summary>
public sealed class TestTimeProvider : TimeProvider
{
    private DateTimeOffset _now;

    public TestTimeProvider(DateTimeOffset start) => _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>Advances a test clock after the first read command — simulates time passing between an
/// operation's initial read and its write, to exercise write-time deadline/expiry rechecks.</summary>
public sealed class AdvanceClockOnFirstReadInterceptor : DbCommandInterceptor
{
    private readonly TestTimeProvider _clock;
    private readonly TimeSpan _by;
    private int _tripped;

    public AdvanceClockOnFirstReadInterceptor(TestTimeProvider clock, TimeSpan by)
    {
        _clock = clock;
        _by = by;
    }

    public override DbDataReader ReaderExecuted(
        DbCommand command, CommandExecutedEventData eventData, DbDataReader result)
    {
        Trip();
        return result;
    }

    public override ValueTask<DbDataReader> ReaderExecutedAsync(
        DbCommand command, CommandExecutedEventData eventData, DbDataReader result,
        CancellationToken cancellationToken = default)
    {
        Trip();
        return new ValueTask<DbDataReader>(result);
    }

    private void Trip()
    {
        if (Interlocked.Exchange(ref _tripped, 1) == 0)
            _clock.Advance(_by);
    }
}

/// <summary>On the first SaveChanges, externally bumps the target row's RowVersion (forcing a CAS conflict)
/// and advances the clock — used to prove the verify retry re-evaluates expiry from the store clock.</summary>
public sealed class ConflictAndAdvanceOnFirstSaveInterceptor : SaveChangesInterceptor
{
    private readonly Func<TestEmailOtpDbContext> _contextFactory;
    private readonly Guid _challengeId;
    private readonly TestTimeProvider _clock;
    private readonly TimeSpan _advance;
    private int _tripped;

    public ConflictAndAdvanceOnFirstSaveInterceptor(
        Func<TestEmailOtpDbContext> contextFactory, Guid challengeId, TestTimeProvider clock, TimeSpan advance)
    {
        _contextFactory = contextFactory;
        _challengeId = challengeId;
        _clock = clock;
        _advance = advance;
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _tripped, 1) == 0)
        {
            await using var ctx = _contextFactory();
            var row = await ctx.Set<EmailOtpChallenge>().FirstAsync(c => c.Id == _challengeId, cancellationToken);
            row.RowVersion = Guid.NewGuid().ToByteArray(); // bump so the in-flight save hits a RowVersion conflict
            await ctx.SaveChangesAsync(cancellationToken);
            _clock.Advance(_advance); // and time crosses the expiry before the retry re-reads
        }
        return result;
    }
}

/// <summary>Always throws a simulated transient-lock error on save — to prove a failed activation rolls back
/// and never loses the existing active challenge.</summary>
public sealed class ThrowTransientOnSaveInterceptor : SaveChangesInterceptor
{
    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        => throw new InvalidOperationException("database is locked (simulated transient)");
}

/// <summary>Consumer DbContext that registers only the EmailOtp mapping.</summary>
public sealed class TestEmailOtpDbContext : DbContext
{
    public TestEmailOtpDbContext(DbContextOptions<TestEmailOtpDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
        => modelBuilder.AddEmailOtp();
}
