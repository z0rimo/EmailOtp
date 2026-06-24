using System.Data;
using System.Data.Common;
using System.Security.Cryptography;
using EmailOtp;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace EmailOtp.EntityFramework;

/// <summary>
/// EF Core <see cref="IEmailOtpStore"/> implementation. <typeparamref name="TContext"/> is the consumer
/// DbContext that registered the <see cref="EmailOtpChallenge"/> mapping via
/// <see cref="ModelBuilderExtensions.AddEmailOtp"/>.
///
/// Concurrency is built on the rotated <see cref="EmailOtpChallenge.RowVersion"/> token plus the filtered
/// unique index on (Email, Purpose) WHERE Status = Active. Verify/invalidate load the current row, apply
/// their change, and save under the token; a conflict reloads and retries (bounded). Activation supersedes
/// the old active and promotes the pending atomically inside one transaction (rollback restores the old
/// active if anything fails). On SQLite the transaction is BEGIN IMMEDIATE, taking write ownership at BEGIN,
/// so two overlapping activations serialize there instead of hitting the shared→exclusive lock-upgrade
/// deadlock. An unresolved conflict surfaces as <see cref="EmailOtpConcurrencyException"/> — never as a normal
/// result. Only recognized unique-index / transient-lock / concurrency failures are retried (bounded, with
/// jitter); other database errors propagate unchanged.
/// </summary>
internal sealed class EfEmailOtpStore<TContext> : IEmailOtpStore
    where TContext : DbContext
{
    private const int MaxRetries = 8;

    private readonly TContext _db;
    private readonly TimeProvider _clock;

    public EfEmailOtpStore(TContext db, TimeProvider clock)
    {
        _db = db;
        _clock = clock;
    }

    private DbSet<EmailOtpChallenge> Set => _db.Set<EmailOtpChallenge>();

    public async Task CreatePendingAsync(
        EmailOtpPendingChallenge challenge, CancellationToken cancellationToken = default)
    {
        // A pending row is not Active, so it never collides with the filtered unique index — a plain insert.
        var now = _clock.GetUtcNow();
        var entity = new EmailOtpChallenge
        {
            Id = challenge.Id,
            Email = challenge.Email,
            Purpose = challenge.Purpose,
            CodeHash = challenge.CodeHash,
            ExpiresAt = challenge.DeliveryDeadline, // pre-activation/delivery deadline until promoted
            CreatedAt = challenge.CreatedAt,
            UpdatedAt = now,
            AttemptCount = 0,
            Status = EmailOtpChallengeStatus.PendingDelivery,
            RowVersion = NewToken(),
        };
        Set.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
        Detach(entity);
    }

    public async Task<EmailOtpActivationResult> ActivateAsync(
        Guid challengeId, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        if (lifetime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Activation lifetime must be positive.");

        // Atomic supersede-and-promote inside one transaction (rollback restores the old active if anything
        // fails, so a failed replacement never leaves the slot with no active code). On SQLite the transaction
        // is BEGIN IMMEDIATE: write ownership is taken at BEGIN, so two overlapping activations serialize there
        // instead of hitting the shared->exclusive lock-upgrade deadlock. Recognized concurrency/unique/
        // transient-lock failures roll back and retry (bounded, with jitter); anything else propagates.
        for (var attempt = 0; ; attempt++)
        {
            // Acquire the transaction inside the try so a busy/locked failure on BEGIN IMMEDIATE — the most
            // likely contention point for overlapping activations — is also classified for bounded retry.
            IDbContextTransaction? tx = null;
            DbTransaction? sqliteTx = null;
            var openedConnection = false;
            try
            {
                (tx, sqliteTx, openedConnection) = await BeginActivationTransactionAsync(cancellationToken);

                var pending = await Set.FirstOrDefaultAsync(c => c.Id == challengeId, cancellationToken);
                if (pending is null || pending.Status != EmailOtpChallengeStatus.PendingDelivery)
                {
                    await tx.RollbackAsync(cancellationToken);
                    if (pending is { Status: EmailOtpChallengeStatus.Active })
                        return new EmailOtpActivationResult(pending.ExpiresAt); // already activated — idempotent
                    throw new EmailOtpConcurrencyException("Challenge could not be activated (no longer pending).");
                }

                // On SQLite (BEGIN IMMEDIATE) we hold write ownership, so this clock read and the commit below
                // happen with no further lock waiting — the delivery deadline is evaluated effectively at write
                // time. (On other providers, e.g. SQL Server READ COMMITTED, later reads/writes may still block;
                // that path's deadline timing is unverified — see the SQL Server pre-alpha checklist item.)
                var now = _clock.GetUtcNow();
                if (now >= pending.ExpiresAt)
                {
                    // Deadline passed: expire the stale pending and do NOT supersede the current active — a
                    // delayed older request must never invalidate a newer, still-valid active code.
                    pending.Status = EmailOtpChallengeStatus.Expired;
                    pending.UpdatedAt = now;
                    pending.RowVersion = NewToken();
                    await _db.SaveChangesAsync(cancellationToken);
                    await tx.CommitAsync(cancellationToken);
                    throw new EmailOtpConcurrencyException(
                        "Challenge could not be activated: its pending-delivery deadline has passed. Request a new code.");
                }

                var existing = await Set
                    .Where(c => c.Email == pending.Email
                             && c.Purpose == pending.Purpose
                             && c.Status == EmailOtpChallengeStatus.Active)
                    .ToListAsync(cancellationToken);
                foreach (var c in existing)
                {
                    c.Status = EmailOtpChallengeStatus.Superseded;
                    c.UpdatedAt = now;
                    c.RowVersion = NewToken();
                }
                if (existing.Count > 0)
                    await _db.SaveChangesAsync(cancellationToken);

                pending.Status = EmailOtpChallengeStatus.Active;
                pending.UpdatedAt = now;
                pending.ExpiresAt = now + lifetime;
                pending.RowVersion = NewToken();
                await _db.SaveChangesAsync(cancellationToken);

                await tx.CommitAsync(cancellationToken);
                return new EmailOtpActivationResult(pending.ExpiresAt);
            }
            catch (Exception ex) when (
                ex is DbUpdateConcurrencyException || IsUniqueViolation(ex) || IsTransientLock(ex))
            {
                if (tx is not null)
                    await SafeRollbackAsync(tx, cancellationToken);
                if (attempt >= MaxRetries - 1)
                    throw new EmailOtpConcurrencyException("Activation could not complete due to repeated conflicts.");
                await Task.Delay(Random.Shared.Next(5, 30), cancellationToken); // jitter to break symmetric retries
            }
            finally
            {
                DetachAll();
                if (tx is not null)
                    await tx.DisposeAsync();
                if (sqliteTx is not null)
                    await sqliteTx.DisposeAsync();
                if (openedConnection)
                    await _db.Database.CloseConnectionAsync();
            }
        }
    }

    public async Task<EmailOtpStoreVerificationResult> VerifyAsync(
        string email, string purpose, byte[] candidateHash,
        int maxAttempts, CancellationToken cancellationToken = default)
    {
        for (var retry = 0; retry < MaxRetries; retry++)
        {
            var c = await Set.FirstOrDefaultAsync(
                x => x.Email == email && x.Purpose == purpose && x.Status == EmailOtpChallengeStatus.Active,
                cancellationToken);

            if (c is null)
                return new EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome.NotFound, 0);

            // Read the clock here, immediately before the transition, on every retry — so a request that
            // started before expiry cannot commit after it.
            var now = _clock.GetUtcNow();
            if (c.ExpiresAt <= now)
            {
                c.Status = EmailOtpChallengeStatus.Expired;
                c.UpdatedAt = now;
                c.RowVersion = NewToken();
                if (await TrySaveAsync(c, cancellationToken))
                    return new EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome.Expired, c.AttemptCount);
                continue;
            }

            if (CryptographicOperations.FixedTimeEquals(c.CodeHash, candidateHash))
            {
                c.Status = EmailOtpChallengeStatus.Verified;
                c.UpdatedAt = now;
                c.RowVersion = NewToken();
                if (await TrySaveAsync(c, cancellationToken))
                    return new EmailOtpStoreVerificationResult(EmailOtpStoreVerificationOutcome.Success, c.AttemptCount);
                continue;
            }

            var newCount = c.AttemptCount + 1;
            var locked = newCount >= maxAttempts;
            c.AttemptCount = newCount;
            c.UpdatedAt = now;
            if (locked)
                c.Status = EmailOtpChallengeStatus.Locked;
            c.RowVersion = NewToken();
            if (await TrySaveAsync(c, cancellationToken))
                return new EmailOtpStoreVerificationResult(
                    locked ? EmailOtpStoreVerificationOutcome.MaxAttemptsExceeded : EmailOtpStoreVerificationOutcome.CodeMismatch,
                    newCount);
            // Conflict → reload and retry; never report an uncounted attempt as a normal result.
        }

        throw new EmailOtpConcurrencyException(
            "Verification could not complete due to repeated concurrency conflicts. Please try again.");
    }

    public async Task InvalidateAsync(
        Guid challengeId, EmailOtpStoreInvalidationReason reason, CancellationToken cancellationToken = default)
    {
        for (var retry = 0; retry < MaxRetries; retry++)
        {
            var c = await Set.FirstOrDefaultAsync(x => x.Id == challengeId, cancellationToken);
            if (c is null
                || c.Status is not (EmailOtpChallengeStatus.Active or EmailOtpChallengeStatus.PendingDelivery))
            {
                Detach(c); // idempotent: already terminal (or gone)
                return;
            }

            c.Status = MapStatus(reason);
            c.UpdatedAt = _clock.GetUtcNow();
            c.RowVersion = NewToken();
            if (await TrySaveAsync(c, cancellationToken))
                return;
            // Conflict → reload and retry until the transition lands or the row is confirmed non-active.
        }

        throw new EmailOtpConcurrencyException(
            "Invalidation could not complete due to repeated concurrency conflicts.");
    }

    public async Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
        => await Set.Where(c => c.ExpiresAt <= now).ExecuteDeleteAsync(cancellationToken);

    /// <summary>
    /// Begins the activation transaction. On SQLite it is an IMMEDIATE transaction (write lock acquired at
    /// BEGIN) so overlapping activations serialize there instead of deadlocking on a shared→exclusive upgrade;
    /// other providers use a normal transaction. Returns the EF transaction, the underlying ADO.NET transaction
    /// (SQLite only — caller disposes it), and whether the connection was opened here (caller closes it). On
    /// any failure it cleans up what it acquired and rethrows, so the caller's classified retry can handle a
    /// busy/locked BEGIN.
    /// </summary>
    private async Task<(IDbContextTransaction Tx, DbTransaction? SqliteTx, bool OpenedConnection)>
        BeginActivationTransactionAsync(CancellationToken cancellationToken)
    {
        if (!string.Equals(_db.Database.ProviderName, "Microsoft.EntityFrameworkCore.Sqlite", StringComparison.Ordinal))
            return (await _db.Database.BeginTransactionAsync(cancellationToken), null, false);

        var opened = false;
        DbTransaction? sqliteTx = null;
        try
        {
            await _db.Database.OpenConnectionAsync(cancellationToken);
            opened = true;
            var conn = _db.Database.GetDbConnection();
            var beginImmediate = conn.GetType().GetMethod("BeginTransaction", new[] { typeof(IsolationLevel), typeof(bool) })
                ?? throw new InvalidOperationException("SqliteConnection.BeginTransaction(IsolationLevel, bool) not found.");
            // Reflection avoids a hard Microsoft.Data.Sqlite dependency; a busy/locked SqliteException surfaces
            // wrapped in TargetInvocationException, which IsTransientLock recognizes by walking the chain.
            sqliteTx = (DbTransaction)beginImmediate.Invoke(conn, new object[] { IsolationLevel.Serializable, false })!;
            var tx = await _db.Database.UseTransactionAsync(sqliteTx, cancellationToken)
                     ?? throw new InvalidOperationException("Failed to adopt the SQLite immediate transaction.");
            return (tx, sqliteTx, true);
        }
        catch
        {
            if (sqliteTx is not null) await sqliteTx.DisposeAsync();
            if (opened) await _db.Database.CloseConnectionAsync();
            throw;
        }
    }

    private static async Task SafeRollbackAsync(IDbContextTransaction tx, CancellationToken cancellationToken)
    {
        try { await tx.RollbackAsync(cancellationToken); }
        catch { /* transaction may already be aborted; nothing to undo */ }
    }

    /// <summary>Saves the single tracked change; returns false on a concurrency conflict (caller reloads).</summary>
    private async Task<bool> TrySaveAsync(EmailOtpChallenge tracked, CancellationToken cancellationToken)
    {
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
            Detach(tracked);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(tracked);
            return false;
        }
    }

    /// <summary>
    /// Recognizes a unique-index violation across the tested providers (walking the exception chain). Other
    /// constraint/data errors are deliberately not matched so they propagate instead of being retried.
    /// </summary>
    private static bool IsUniqueViolation(Exception ex)
        => ChainContains(ex,
            "UNIQUE constraint failed",     // SQLite
            "duplicate key",                // SQL Server
            "violates unique constraint");  // PostgreSQL

    /// <summary>Recognizes a transient SQLite busy/locked condition (and SQL Server deadlock) — retryable.</summary>
    private static bool IsTransientLock(Exception ex)
        => ChainContains(ex,
            "database is locked",           // SQLite (SQLITE_BUSY)
            "database table is locked",     // SQLite (SQLITE_LOCKED)
            "deadlock");                    // SQL Server (1205)

    private static bool ChainContains(Exception ex, params string[] needles)
    {
        for (var e = ex; e is not null; e = e.InnerException)
            foreach (var needle in needles)
                if (e.Message.Contains(needle, StringComparison.OrdinalIgnoreCase))
                    return true;
        return false;
    }

    private static EmailOtpChallengeStatus MapStatus(EmailOtpStoreInvalidationReason reason) => reason switch
    {
        EmailOtpStoreInvalidationReason.Expired => EmailOtpChallengeStatus.Expired,
        EmailOtpStoreInvalidationReason.DeliveryFailed => EmailOtpChallengeStatus.DeliveryFailed,
        EmailOtpStoreInvalidationReason.Manual => EmailOtpChallengeStatus.Revoked,
        _ => EmailOtpChallengeStatus.Superseded,
    };

    private static byte[] NewToken() => Guid.NewGuid().ToByteArray();

    private void Detach(EmailOtpChallenge? entity)
    {
        if (entity is not null)
            _db.Entry(entity).State = EntityState.Detached;
    }

    private void DetachAll()
    {
        foreach (var entry in _db.ChangeTracker.Entries<EmailOtpChallenge>().ToList())
            entry.State = EntityState.Detached;
    }
}
