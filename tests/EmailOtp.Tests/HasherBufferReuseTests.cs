using EmailOtp;
using EmailOtp.Tests.Fakes;
using Microsoft.Extensions.Options;

namespace EmailOtp.Tests;

/// <summary>
/// Pins the documented hasher contract — "a hasher may safely reuse its output buffer" — for the verify path.
/// The service must own (copy) the candidate hash before the async store call, or a concurrent verify using a
/// buffer-reusing hasher could overwrite an in-flight candidate and compare a wrong code against another
/// request's hash. Deterministic: a gated store parks both verifies mid-call so the shared buffer is
/// provably overwritten before either comparison runs.
/// </summary>
public class HasherBufferReuseTests
{
    private const string Pepper = "test-pepper-at-least-16-bytes-long!!";
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Adversarial hasher: returns ONE shared array, overwritten on every call.</summary>
    private sealed class SharedBufferHasher : IEmailOtpHasher
    {
        private readonly IEmailOtpHasher _inner;
        private readonly byte[] _buffer = new byte[32]; // HMAC-SHA256 width

        public SharedBufferHasher(IEmailOtpHasher inner) => _inner = inner;

        public byte[] Hash(string code)
        {
            var real = _inner.Hash(code);
            Array.Copy(real, _buffer, real.Length);
            return _buffer; // always the same instance — the worst case the contract tolerates
        }
    }

    /// <summary>Store stub that parks every verify at a gate until released, holding the candidate reference
    /// across the await, then compares it to a fixed correct hash.</summary>
    private sealed class GatedVerifyStore : IEmailOtpStore
    {
        private readonly byte[] _correctHash;
        private readonly TaskCompletionSource _firstReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _secondReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrivals;

        public GatedVerifyStore(byte[] correctHash) => _correctHash = correctHash;

        public Task FirstReceived => _firstReceived.Task;
        public Task SecondReceived => _secondReceived.Task;
        public void Release() => _release.TrySetResult();

        public async Task<EmailOtpStoreVerificationResult> VerifyAsync(
            string email, string purpose, byte[] candidateHash, int maxAttempts,
            CancellationToken cancellationToken = default)
        {
            var n = Interlocked.Increment(ref _arrivals);
            if (n == 1) _firstReceived.TrySetResult();
            if (n == 2) _secondReceived.TrySetResult();
            await _release.Task; // both verifies suspend here, candidate references captured

            var match = candidateHash.AsSpan().SequenceEqual(_correctHash);
            return new EmailOtpStoreVerificationResult(
                match ? EmailOtpStoreVerificationOutcome.Success : EmailOtpStoreVerificationOutcome.CodeMismatch, 0);
        }

        public Task CreatePendingAsync(EmailOtpPendingChallenge challenge, CancellationToken ct = default)
            => throw new NotSupportedException();
        public Task<EmailOtpActivationResult> ActivateAsync(Guid id, TimeSpan lifetime, CancellationToken ct = default)
            => throw new NotSupportedException();
        public Task InvalidateAsync(Guid id, EmailOtpStoreInvalidationReason reason, CancellationToken ct = default)
            => throw new NotSupportedException();
        public Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken ct = default)
            => throw new NotSupportedException();
    }

    [Fact]
    public async Task Concurrent_verify_with_buffer_reusing_hasher_does_not_cross_contaminate()
    {
        var options = new EmailOtpOptions { Secret = Pepper };
        options.Validate();
        var plain = new HmacEmailOtpHasher(Options.Create(options));
        var correctHash = (byte[])plain.Hash("111111").Clone(); // the verify-success target

        var store = new GatedVerifyStore(correctHash);
        var svc = new EmailOtpService(
            Options.Create(options),
            store,
            new SequenceEmailOtpCodeGenerator(), // unused by verify
            new SharedBufferHasher(new HmacEmailOtpHasher(Options.Create(options))),
            new CapturingEmailOtpSender(),
            new DefaultEmailOtpEmailNormalizer(Options.Create(options)),
            new TestTimeProvider(T0));

        // A: correct code. Parks in the store holding its candidate; then B's hashing overwrites the shared
        // buffer. If A didn't copy its hash before the await, A now points at B's (wrong) hash.
        var taskA = Task.Run(() => svc.VerifyAsync("user@example.com", "111111"));
        await store.FirstReceived;

        var taskB = Task.Run(() => svc.VerifyAsync("user@example.com", "999999"));
        await store.SecondReceived; // B has hashed (shared buffer now holds the wrong code's hash) and parked

        store.Release();
        var rA = await taskA;
        var rB = await taskB;

        Assert.True(rA.Succeeded);  // correct code still succeeds despite the buffer-reusing hasher
        Assert.False(rB.Succeeded); // wrong code fails
    }
}
