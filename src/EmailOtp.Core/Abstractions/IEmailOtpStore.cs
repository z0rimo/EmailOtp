namespace EmailOtp;

/// <summary>
/// Storage contract for email-OTP challenges, expressed as domain actions over immutable command/result
/// types — the persistence model (rows, status, concurrency token) is owned privately by each adapter, not
/// exposed here. This is an <b>advanced extensibility</b> interface (custom Dapper/Redis store); typical
/// consumers use the EF Core adapter and never implement it.
/// <para>Implementations must be linearizable under concurrency:</para>
/// <list type="bullet">
///   <item>at most one active challenge per (email, purpose);</item>
///   <item><see cref="VerifyAsync"/> atomically checks active state, expiry and the candidate hash, then
///   consumes (on match) or increments/locks (on mismatch) in a single linearizable step — so the attempt
///   cap bounds the number of guesses even under parallel requests;</item>
///   <item>activation supersedes the previous active and promotes the pending atomically (a rollback restores
///   the old active if it fails);</item>
///   <item>internal concurrency conflicts are resolved by retry inside the implementation; an unresolved
///   conflict surfaces as <see cref="EmailOtpConcurrencyException"/>, never as a normal result.</item>
/// </list>
/// </summary>
public interface IEmailOtpStore
{
    /// <summary>
    /// Persists <paramref name="challenge"/> in a not-yet-delivered (non-verifiable) state, without touching
    /// the current active challenge. First half of crash-safe issuance: deliver the code, then call
    /// <see cref="ActivateAsync"/>.
    /// </summary>
    Task CreatePendingAsync(EmailOtpPendingChallenge challenge, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically promotes the pending challenge to active, superseding any existing active challenge for the
    /// same (email, purpose). Called only after the code was delivered. If the pending challenge's delivery
    /// deadline has already passed it is expired instead and the current active is <b>not</b> superseded, so a
    /// delayed older request can never invalidate a newer, still-valid active code. Otherwise the store stamps
    /// a fresh verification expiry <c>now + <paramref name="lifetime"/></c> and returns it.
    /// Throws <see cref="EmailOtpConcurrencyException"/> if it cannot be activated (no longer pending, or its
    /// delivery deadline passed), or <see cref="ArgumentOutOfRangeException"/> if <paramref name="lifetime"/>
    /// is non-positive.
    /// </summary>
    Task<EmailOtpActivationResult> ActivateAsync(
        Guid challengeId, TimeSpan lifetime, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically verifies a candidate against the active challenge for (email, purpose): checks it exists, is
    /// unexpired, then either consumes it (hash match) or counts the failed attempt, locking at
    /// <paramref name="maxAttempts"/>. <paramref name="candidateHash"/> is the hash of the submitted code; the
    /// store compares it against the stored hash in fixed time.
    /// </summary>
    Task<EmailOtpStoreVerificationResult> VerifyAsync(
        string email, string purpose, byte[] candidateHash,
        int maxAttempts, CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidates a challenge that is still active or pending, moving it to a terminal state with the given
    /// reason. Retries on concurrency conflict until the transition succeeds or the row is confirmed already
    /// terminal (idempotent no-op).
    /// </summary>
    Task InvalidateAsync(
        Guid challengeId, EmailOtpStoreInvalidationReason reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Maintenance cleanup — <b>not</b> an audit-log retention mechanism. Deletes every challenge whose expiry
    /// is at or before <paramref name="now"/>, regardless of status (including expired-but-active rows);
    /// non-expired rows are kept whatever their status. Returns the number removed. Run it periodically
    /// (e.g. a background job); record an audit trail separately if you need history.
    /// </summary>
    Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default);
}
