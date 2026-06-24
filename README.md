# EmailOtp

**English** | [한국어](README.ko.md)

**Email magic code (one-time password) for passwordless login in ASP.NET Core.**

> ⚠️ This is **not** TOTP/HOTP (e.g. `Otp.NET`, Google Authenticator). There is no shared
> secret and no time-window algorithm. Instead, the server **generates a short-lived code,
> delivers it (email/SMS/your choice), and manages its full lifecycle** in your database —
> the "we emailed you a 6-digit code" pattern used by Slack, Notion, etc.

[![CI](https://github.com/z0rimo/emailotp_2/actions/workflows/ci.yml/badge.svg)](https://github.com/z0rimo/emailotp_2/actions/workflows/ci.yml)

## Why

ASP.NET Core has no first-class "email a login code" primitive. Rolling your own usually
misses the parts that matter: **atomic single-use consumption**, **brute-force attempt caps
under concurrency**, and **safe hashing of a tiny code space**. EmailOtp packages exactly
that, and nothing else — it does **not** create users or issue tokens. Verifying a code only
proves the person controls the inbox; what you do next (look up/create a user, issue a JWT or
cookie) stays your application's job.

## Model

EmailOtp keeps **one active challenge per `(email, purpose)` slot**. A new code is stored as
`PendingDelivery` and only **activated after it has been delivered**, superseding the previous code — so a
slot never has two live codes and an undelivered code is never verifiable. A challenge moves through a
small lifecycle — `PendingDelivery → Active → (Verified | Superseded | Expired | Locked)`, or
`PendingDelivery → DeliveryFailed` — and a filtered unique index plus an optimistic-concurrency token keep
the single-active invariant under concurrent requests.

## Security

- Codes are stored as **HMAC-SHA256 with a server-side pepper**, never as plaintext or a bare
  SHA-256. A 6-digit code has only 1,000,000 possibilities — a keyless hash is trivially
  reversible from a database dump. The pepper (kept **outside** the database, e.g. an env var)
  blocks that.
- **Single-use**: a verified code is consumed atomically (optimistic concurrency), so it can't
  be replayed or double-spent under a race.
- **Attempt cap**: wrong guesses are counted with a compare-and-set; reaching the cap immediately
  **locks** the challenge, so the cap holds even under concurrent submissions.
- **Crash-safe issuance / no code left behind**: a new code is stored as `PendingDelivery` and isn't
  verifiable until delivery succeeds, at which point it's atomically activated. A crash or delivery failure
  before activation leaves the previous code intact and never activates an undelivered one; abandoned
  pending rows expire and are removed by `PurgeExpiredAsync`. If delivery is so slow that the pending code's
  delivery deadline has passed, activation is rejected (the pending expires) rather than superseding a newer,
  still-valid active code.
- Don't echo `FailureReason` **or** `RemainingAttempts` to end users — keep responses generic (see
  below). Treat both as logging / metrics / internal-handling only.

> **Rate limiting is your responsibility.** The per-challenge attempt cap stops guessing a *single* code; it
> does **not** stop request spam, repeated challenge replacement, distributed abuse, or endpoint flooding.
> Add application-level throttling on both the request and verify endpoints, keyed by email, IP, and any
> broader abuse signals, before exposing this publicly.

## Install

```bash
dotnet add package EmailOtp                 # storage-agnostic core
dotnet add package EmailOtp.EntityFramework # EF Core storage adapter
```

Target framework: **net8.0+**.

## Quickstart (ASP.NET Core + EF Core)

**1. Map the entity on your DbContext:**

```csharp
using EmailOtp.EntityFramework;

public class AppDbContext : DbContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
        => modelBuilder.AddEmailOtp();   // adds the EmailOtpChallenges table
}
```

**2. Implement delivery (`IEmailOtpSender`):**

```csharp
public sealed class SmtpOtpSender : IEmailOtpSender
{
    public Task SendAsync(string email, string code, string purpose, CancellationToken ct = default)
    {
        // send `code` to `email` however you like
        return Task.CompletedTask;
    }
}
```

**3. Register (pepper comes from an env var / secret store, never the DB):**

```csharp
builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlServer(connectionString));

builder.Services
    .AddEmailOtp(o => o.Secret = builder.Configuration["EMAILOTP_PEPPER"]!)
    .UseEntityFramework<AppDbContext>()
    .AddSender<SmtpOtpSender>();
```

**4. Use it in an endpoint:**

```csharp
app.MapPost("/auth/request-code", async (string email, IEmailOtpService otp) =>
{
    await otp.RequestAsync(email);
    return Results.Ok();   // don't reveal whether the address exists
});

app.MapPost("/auth/verify-code", async (string email, string code, IEmailOtpService otp) =>
{
    var result = await otp.VerifyAsync(email, code);
    if (!result.Succeeded)
        return Results.BadRequest("Invalid or expired code.");   // keep it generic

    // result.FailureReason / RemainingAttempts are available for logging/metrics,
    // but don't echo them to the caller.

    // ↓ your application's job — EmailOtp stops here
    // var user = await users.GetOrCreateAsync(result.Email);
    // var jwt  = tokens.Issue(user);
    return Results.Ok();
});
```

Don't forget to create the `EmailOtpChallenges` table (an EF migration, or `EnsureCreated` in dev).

## Configuration (`EmailOtpOptions`)

| Option                            | Default      | Notes |
|-----------------------------------|--------------|-------|
| `Secret`                          | *(required)* | HMAC pepper. ≥16 bytes. Keep out of the database. |
| `CodeLength`                      | `6`          | 4–12 digits. |
| `Expiry`                          | `10 min`     | Code lifetime. |
| `MaxAttempts`                     | `5`          | Wrong guesses before the challenge is locked. |
| `NormalizeEmailToLowerInvariant`  | `true`       | Lower-case the email during normalization. |
| `MaxEmailLength`                  | `320`        | Rejects longer emails. |
| `MaxPurposeLength`                | `64`         | Rejects longer purposes. |

Invalid configuration (e.g. a missing/short pepper) fails fast at startup via `ValidateOnStart`.

## Purpose (multi-use)

`RequestAsync`/`VerifyAsync` take a `purpose` (default `"login"`). The same email can hold
independent codes per purpose — `"login"`, `"email-change"`, `"password-reset"`, etc.

## Providers & storage notes

- **Provider support:** SQLite is **integration-tested** (full suite, real DB, including concurrent
  stress tests). SQL Server is **live-tested** (request/verify flow verified against a real SQL Server;
  concurrent stress tests not yet run). **All other providers are unsupported until tested** — they may
  work, but that is unverified.
- **Concurrent issuance:** activation supersedes the old code and promotes the new one **atomically in one
  transaction** (a rollback restores the old active if anything fails, so a failed replacement never leaves the
  slot with no code). On SQLite the transaction is **`BEGIN IMMEDIATE`**, which takes write ownership at BEGIN
  so two overlapping same-slot activations serialize there instead of hitting the shared→exclusive lock-upgrade
  deadlock — and the delivery-deadline check is evaluated after that write ownership is held. Verified on
  SQLite (genuinely parallel + rollback tests). SQL Server live use is verified; concurrent activation
  stress tests (whether the deadline check holds under lock waiting with row locks + normal transaction)
  are **not yet run**. Recognized transient-lock / concurrency conflicts are
  retried (bounded, with jitter); a persistent conflict surfaces as a transient `EmailOtpConcurrencyException`
  (retry the request).
- **Single-active-slot** is enforced by a **filtered unique index** on `(Email, Purpose) WHERE [Status] = 0`.
  This requires a provider that supports partial/filtered unique indexes — SQLite and SQL Server emit it as
  written. Other providers are not covered by CI. PostgreSQL supports partial indexes but quotes identifiers
  differently, so pass a provider-appropriate filter:
  ```csharp
  modelBuilder.AddEmailOtp(activeIndexFilter: "\"Status\" = 0"); // e.g. PostgreSQL
  ```
- **Concurrency token:** `RowVersion` is an **application-managed** token — the store rotates it on every
  write. It deliberately does **not** rely on SQL Server's auto-updating `rowversion`, so optimistic
  concurrency works the same on providers without one (e.g. SQLite).
- **`PurgeExpiredAsync(now)`** is a **maintenance cleanup, not audit-log retention**. It deletes every
  challenge with `ExpiresAt <= now` regardless of status (including expired-but-active rows); non-expired
  rows are kept. Run it periodically from a background job, and record an audit trail separately if you
  need history.

## Extensibility

Everything is an interface with a sensible built-in default. The default implementations are internal and
registered for you by `AddEmailOtp()` / `UseEntityFramework()`; to swap one, register your own implementation
of the interface (a later registration wins).

| Interface                   | Built-in default                          | Swap for… |
|-----------------------------|-------------------------------------------|-----------|
| `IEmailOtpStore`            | EF Core (`UseEntityFramework<TContext>`)  | Dapper, Redis, … |
| `IEmailOtpSender`           | *(you provide)*                           | SMTP, SES, SMS, console |
| `IEmailOtpCodeGenerator`    | numeric code                              | alphanumeric, custom length |
| `IEmailOtpHasher`           | HMAC-SHA256 + pepper                       | custom KDF |
| `IEmailOtpEmailNormalizer`  | trim + lower-invariant                    | custom normalization |

`IEmailOtpStore` also exposes `PurgeExpiredAsync(now)` for periodic cleanup of expired rows.

## License

MIT
