using EmailOtp;

namespace EmailOtp.Tests.Fakes;

/// <summary>Test-local lifecycle status (the real persisted enum is internal to the EF adapter).</summary>
public enum TestChallengeStatus
{
    PendingDelivery,
    Active,
    Verified,
    Superseded,
    Expired,
    Locked,
    DeliveryFailed,
    Revoked,
}

/// <summary>Snapshot of an in-memory challenge for test assertions.</summary>
public sealed record TestChallengeSnapshot(
    Guid Id, string Email, string Purpose, TestChallengeStatus Status, int AttemptCount,
    DateTimeOffset ExpiresAt, byte[] CodeHash);

/// <summary>
/// In-memory <see cref="IEmailOtpStore"/> for Core tests. A single lock makes every operation atomic,
/// faithfully modeling the contract (single active slot, atomic verify/consume, attempt cap with lock).
/// Real concurrency/conflict behavior is exercised separately by the EF/SQLite tests. It keeps its own
/// private representation — it does not depend on the EF adapter's internal entity.
/// </summary>
public sealed class InMemoryEmailOtpStore : IEmailOtpStore
{
    private sealed class Row
    {
        public required Guid Id { get; init; }
        public required string Email { get; init; }
        public required string Purpose { get; init; }
        public required byte[] CodeHash { get; init; }
        public required DateTimeOffset CreatedAt { get; init; }
        public DateTimeOffset ExpiresAt { get; set; }
        public int AttemptCount { get; set; }
        public TestChallengeStatus Status { get; set; }
    }

    private readonly Dictionary<Guid, Row> _store = new();
    private readonly object _gate = new();
    private readonly TimeProvider _clock;

    public InMemoryEmailOtpStore(TimeProvider? clock = null) => _clock = clock ?? TimeProvider.System;

    public Task CreatePendingAsync(EmailOtpPendingChallenge challenge, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _store[challenge.Id] = new Row
            {
                Id = challenge.Id,
                Email = challenge.Email,
                Purpose = challenge.Purpose,
                CodeHash = challenge.CodeHash,
                CreatedAt = challenge.CreatedAt,
                ExpiresAt = challenge.DeliveryDeadline,
                AttemptCount = 0,
                Status = TestChallengeStatus.PendingDelivery,
            };
            return Task.CompletedTask;
        }
    }

    public Task<EmailOtpActivationResult> ActivateAsync(
        Guid challengeId, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        if (lifetime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Activation lifetime must be positive.");

        lock (_gate)
        {
            if (!_store.TryGetValue(challengeId, out var pending))
                throw new EmailOtpConcurrencyException("Challenge to activate no longer exists.");
            if (pending.Status == TestChallengeStatus.Active)
                return Task.FromResult(new EmailOtpActivationResult(pending.ExpiresAt));
            if (pending.Status != TestChallengeStatus.PendingDelivery)
                throw new EmailOtpConcurrencyException("Challenge is not pending activation.");

            var now = _clock.GetUtcNow();
            if (now >= pending.ExpiresAt)
            {
                pending.Status = TestChallengeStatus.Expired;
                throw new EmailOtpConcurrencyException(
                    "Challenge could not be activated: its pending-delivery deadline has passed. Request a new code.");
            }

            foreach (var c in _store.Values)
            {
                if (c.Email == pending.Email && c.Purpose == pending.Purpose && c.Status == TestChallengeStatus.Active)
                    c.Status = TestChallengeStatus.Superseded;
            }

            pending.Status = TestChallengeStatus.Active;
            pending.ExpiresAt = now + lifetime;
            return Task.FromResult(new EmailOtpActivationResult(pending.ExpiresAt));
        }
    }

    public Task<EmailOtpStoreVerificationResult> VerifyAsync(
        string email, string purpose, byte[] candidateHash, int maxAttempts, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            var c = _store.Values
                .Where(x => x.Email == email && x.Purpose == purpose && x.Status == TestChallengeStatus.Active)
                .OrderByDescending(x => x.CreatedAt)
                .FirstOrDefault();

            if (c is null)
                return Task.FromResult(new EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome.NotFound, 0));

            var now = _clock.GetUtcNow();
            if (c.ExpiresAt <= now)
            {
                c.Status = TestChallengeStatus.Expired;
                return Task.FromResult(new EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome.Expired, c.AttemptCount));
            }

            if (c.CodeHash.AsSpan().SequenceEqual(candidateHash))
            {
                c.Status = TestChallengeStatus.Verified;
                return Task.FromResult(new EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome.Success, c.AttemptCount));
            }

            c.AttemptCount++;
            if (c.AttemptCount >= maxAttempts)
            {
                c.Status = TestChallengeStatus.Locked;
                return Task.FromResult(new EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome.MaxAttemptsExceeded, c.AttemptCount));
            }
            return Task.FromResult(new EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome.CodeMismatch, c.AttemptCount));
        }
    }

    public Task InvalidateAsync(
        Guid challengeId, EmailOtpStoreInvalidationReason reason, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_store.TryGetValue(challengeId, out var c)
                && c.Status is TestChallengeStatus.Active or TestChallengeStatus.PendingDelivery)
            {
                c.Status = reason switch
                {
                    EmailOtpStoreInvalidationReason.Expired => TestChallengeStatus.Expired,
                    EmailOtpStoreInvalidationReason.DeliveryFailed => TestChallengeStatus.DeliveryFailed,
                    EmailOtpStoreInvalidationReason.Manual => TestChallengeStatus.Revoked,
                    _ => TestChallengeStatus.Superseded,
                };
            }
            return Task.CompletedTask;
        }
    }

    public Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            var ids = _store.Values.Where(c => c.ExpiresAt <= now).Select(c => c.Id).ToList();
            foreach (var id in ids) _store.Remove(id);
            return Task.FromResult(ids.Count);
        }
    }

    /// <summary>Test accessor — snapshot of all stored challenges.</summary>
    public IReadOnlyList<TestChallengeSnapshot> All()
    {
        lock (_gate)
        {
            return _store.Values
                .Select(c => new TestChallengeSnapshot(
                    c.Id, c.Email, c.Purpose, c.Status, c.AttemptCount, c.ExpiresAt, c.CodeHash))
                .ToList();
        }
    }
}
