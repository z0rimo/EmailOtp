using EmailOtp;
using EmailOtp.Tests.Fakes;
using Microsoft.Extensions.Options;

namespace EmailOtp.Tests;

/// <summary>
/// Core contract tests for <see cref="EmailOtpService"/> using the in-memory store and a deterministic
/// code sequence (no reliance on random-code coincidence).
/// </summary>
public class EmailOtpServiceTests
{
    private const string Pepper = "test-pepper-at-least-16-bytes-long!!";
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private sealed class Harness
    {
        public required EmailOtpService Service { get; init; }
        public required InMemoryEmailOtpStore Store { get; init; }
        public required CapturingEmailOtpSender Sender { get; init; }
        public required TestTimeProvider Clock { get; init; }
    }

    private static Harness Build(
        string[] codes,
        Action<EmailOtpOptions>? configure = null,
        IEmailOtpSender? sender = null)
    {
        var options = new EmailOtpOptions { Secret = Pepper };
        configure?.Invoke(options);
        options.Validate();

        var clock = new TestTimeProvider(T0);
        var store = new InMemoryEmailOtpStore(clock);
        var capturing = sender as CapturingEmailOtpSender ?? new CapturingEmailOtpSender();

        var service = new EmailOtpService(
            Options.Create(options),
            store,
            new SequenceEmailOtpCodeGenerator(codes),
            new HmacEmailOtpHasher(Options.Create(options)),
            sender ?? capturing,
            new DefaultEmailOtpEmailNormalizer(Options.Create(options)),
            clock);

        return new Harness { Service = service, Store = store, Sender = capturing, Clock = clock };
    }

    [Fact]
    public async Task Request_issues_code_and_delivers_it()
    {
        var h = Build(["123456"]);

        var result = await h.Service.RequestAsync("user@example.com");

        Assert.Equal("user@example.com", result.Email);
        Assert.Equal(EmailOtpPurposes.Login, result.Purpose);
        Assert.Equal(T0 + TimeSpan.FromMinutes(10), result.ExpiresAt);
        Assert.Equal("123456", h.Sender.LastCode);
        Assert.Single(h.Store.All(), c => c.Status == TestChallengeStatus.Active);
    }

    [Fact]
    public async Task Verify_with_correct_code_succeeds()
    {
        var h = Build(["123456"]);
        await h.Service.RequestAsync("user@example.com");

        var result = await h.Service.VerifyAsync("user@example.com", "123456");

        Assert.True(result.Succeeded);
        Assert.Equal("user@example.com", result.Email);
    }

    [Fact]
    public async Task Verify_with_wrong_code_fails_with_decremented_remaining()
    {
        var h = Build(["123456"], o => o.MaxAttempts = 5);
        await h.Service.RequestAsync("user@example.com");

        var result = await h.Service.VerifyAsync("user@example.com", "000000");

        Assert.False(result.Succeeded);
        Assert.Equal(EmailOtpFailureReason.CodeMismatch, result.FailureReason);
        Assert.Equal(4, result.RemainingAttempts);
    }

    [Fact]
    public async Task Verify_expired_code_fails()
    {
        var h = Build(["123456"]);
        await h.Service.RequestAsync("user@example.com");

        h.Clock.Advance(TimeSpan.FromMinutes(11)); // past the 10-minute expiry

        var result = await h.Service.VerifyAsync("user@example.com", "123456");

        Assert.False(result.Succeeded);
        Assert.Equal(EmailOtpFailureReason.Expired, result.FailureReason);
        Assert.Single(h.Store.All(), c => c.Status == TestChallengeStatus.Expired);
    }

    [Fact]
    public async Task Used_code_cannot_be_reused()
    {
        var h = Build(["123456"]);
        await h.Service.RequestAsync("user@example.com");

        Assert.True((await h.Service.VerifyAsync("user@example.com", "123456")).Succeeded);

        var second = await h.Service.VerifyAsync("user@example.com", "123456");
        Assert.False(second.Succeeded);
        Assert.Equal(EmailOtpFailureReason.NotFound, second.FailureReason);
    }

    [Fact]
    public async Task Purpose_mismatch_fails()
    {
        var h = Build(["111111", "222222"]);
        await h.Service.RequestAsync("user@example.com", "login");
        await h.Service.RequestAsync("user@example.com", "email-change");

        // The login code is not valid under a different purpose.
        var wrong = await h.Service.VerifyAsync("user@example.com", "111111", "email-change");
        Assert.False(wrong.Succeeded);

        var right = await h.Service.VerifyAsync("user@example.com", "111111", "login");
        Assert.True(right.Succeeded);
    }

    [Fact]
    public async Task Email_casing_is_normalized()
    {
        var h = Build(["123456"]);
        await h.Service.RequestAsync("User@Example.COM");

        var result = await h.Service.VerifyAsync("user@example.com", "123456");
        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Reaching_max_attempts_locks_immediately()
    {
        var h = Build(["123456"], o => o.MaxAttempts = 3);
        await h.Service.RequestAsync("user@example.com");

        var r1 = await h.Service.VerifyAsync("user@example.com", "000000");
        var r2 = await h.Service.VerifyAsync("user@example.com", "000000");
        var r3 = await h.Service.VerifyAsync("user@example.com", "000000");

        Assert.Equal(EmailOtpFailureReason.CodeMismatch, r1.FailureReason);
        Assert.Equal(2, r1.RemainingAttempts);
        Assert.Equal(EmailOtpFailureReason.CodeMismatch, r2.FailureReason);
        Assert.Equal(1, r2.RemainingAttempts);
        Assert.Equal(EmailOtpFailureReason.MaxAttemptsExceeded, r3.FailureReason);
        Assert.Equal(0, r3.RemainingAttempts);
        Assert.Single(h.Store.All(), c => c.Status == TestChallengeStatus.Locked);
    }

    [Fact]
    public async Task Correct_code_after_lock_still_fails()
    {
        var h = Build(["123456"], o => o.MaxAttempts = 3);
        await h.Service.RequestAsync("user@example.com");

        for (var i = 0; i < 3; i++)
            await h.Service.VerifyAsync("user@example.com", "000000");

        var result = await h.Service.VerifyAsync("user@example.com", "123456");
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task Delivery_failure_invalidates_challenge_and_propagates()
    {
        var h = Build(["123456"], sender: new ThrowingEmailOtpSender());

        await Assert.ThrowsAsync<ThrowingEmailOtpSender.DeliveryException>(
            () => h.Service.RequestAsync("user@example.com"));

        // No active code is left behind for an undelivered message.
        Assert.DoesNotContain(h.Store.All(), c => c.Status == TestChallengeStatus.Active);
        Assert.Single(h.Store.All(), c => c.Status == TestChallengeStatus.DeliveryFailed);
    }

    [Fact]
    public async Task Request_after_delivery_failure_can_create_new_active_challenge()
    {
        var options = new EmailOtpOptions { Secret = Pepper };
        options.Validate();
        var clock = new TestTimeProvider(T0);
        var store = new InMemoryEmailOtpStore(clock);
        var sender = new FailThenCaptureEmailOtpSender(failures: 1);
        var svc = new EmailOtpService(
            Options.Create(options),
            store,
            new SequenceEmailOtpCodeGenerator("111111", "222222"),
            new HmacEmailOtpHasher(Options.Create(options)),
            sender,
            new DefaultEmailOtpEmailNormalizer(Options.Create(options)),
            clock);

        // First request: delivery fails → challenge invalidated, nothing left active.
        await Assert.ThrowsAsync<ThrowingEmailOtpSender.DeliveryException>(
            () => svc.RequestAsync("user@example.com"));
        Assert.DoesNotContain(store.All(), c => c.Status == TestChallengeStatus.Active);

        // Second request for the same slot: succeeds and creates a fresh active challenge.
        await svc.RequestAsync("user@example.com");
        Assert.Single(store.All(), c => c.Status == TestChallengeStatus.Active);
        Assert.Equal("222222", sender.LastCode);

        // And the new code verifies.
        Assert.True((await svc.VerifyAsync("user@example.com", "222222")).Succeeded);
    }

    [Fact]
    public async Task Leading_zero_code_is_preserved_as_string()
    {
        var h = Build(["000123"]);
        await h.Service.RequestAsync("user@example.com");

        // The code is a string end-to-end — leading zeros are not lost to numeric coercion.
        Assert.Equal("000123", h.Sender.LastCode);
        Assert.True((await h.Service.VerifyAsync("user@example.com", "000123")).Succeeded);
    }

    [Fact]
    public async Task Numeric_equivalent_of_a_leading_zero_code_does_not_verify()
    {
        var h = Build(["000123"]);
        await h.Service.RequestAsync("user@example.com");

        // "123" must NOT match "000123" — codes are compared as strings, not numbers.
        var result = await h.Service.VerifyAsync("user@example.com", "123");
        Assert.False(result.Succeeded);
        Assert.Equal(EmailOtpFailureReason.CodeMismatch, result.FailureReason);
    }

    [Fact]
    public async Task Delivery_failure_of_superseded_request_does_not_invalidate_new_active_challenge()
    {
        var options = new EmailOtpOptions { Secret = Pepper };
        options.Validate();
        var clock = new TestTimeProvider(T0);
        var store = new InMemoryEmailOtpStore(clock);
        var hasher = new HmacEmailOtpHasher(Options.Create(options));
        var normalizer = new DefaultEmailOtpEmailNormalizer(Options.Create(options));

        // Request B is the fast one: it supersedes A and becomes the new active challenge.
        var senderB = new CapturingEmailOtpSender();
        var serviceB = new EmailOtpService(
            Options.Create(options), store, new SequenceEmailOtpCodeGenerator("222222"),
            hasher, senderB, normalizer, clock);

        // Request A is slow: while "sending", B runs to completion, then A's delivery fails.
        var senderA = new CallbackThenThrowEmailOtpSender(() => serviceB.RequestAsync("user@example.com"));
        var serviceA = new EmailOtpService(
            Options.Create(options), store, new SequenceEmailOtpCodeGenerator("111111"),
            hasher, senderA, normalizer, clock);

        await Assert.ThrowsAsync<ThrowingEmailOtpSender.DeliveryException>(
            () => serviceA.RequestAsync("user@example.com"));

        var rows = store.All();
        // Exactly one active challenge — B's — untouched by A's delivery failure.
        Assert.Single(rows, c => c.Status == TestChallengeStatus.Active);
        // A never activated (it failed delivery while pending) → DeliveryFailed, not Active.
        Assert.Contains(rows, c => c.Status == TestChallengeStatus.DeliveryFailed);
        // B's code still verifies.
        Assert.True((await serviceB.VerifyAsync("user@example.com", "222222")).Succeeded);
    }

    [Fact]
    public async Task Raw_code_is_never_stored()
    {
        var h = Build(["123456"]);
        await h.Service.RequestAsync("user@example.com");

        var challenge = Assert.Single(h.Store.All());
        Assert.NotEqual(System.Text.Encoding.UTF8.GetBytes("123456"), challenge.CodeHash);
        Assert.Equal(32, challenge.CodeHash.Length); // HMAC-SHA256 = 32 bytes
    }

    [Fact]
    public void Different_secret_yields_different_hash()
    {
        var a = new HmacEmailOtpHasher(Options.Create(new EmailOtpOptions { Secret = Pepper }));
        var b = new HmacEmailOtpHasher(Options.Create(new EmailOtpOptions { Secret = "another-pepper-16+bytes-value!!" }));

        Assert.NotEqual(a.Hash("123456"), b.Hash("123456"));
    }

    [Fact]
    public async Task Oversized_code_is_rejected_before_hashing()
    {
        var options = new EmailOtpOptions { Secret = Pepper };
        options.Validate();
        var clock = new TestTimeProvider(T0);
        var store = new InMemoryEmailOtpStore(clock);
        var spyHasher = new SpyEmailOtpHasher(new HmacEmailOtpHasher(Options.Create(options)));
        var svc = new EmailOtpService(
            Options.Create(options), store, new SequenceEmailOtpCodeGenerator("123456"),
            spyHasher, new CapturingEmailOtpSender(),
            new DefaultEmailOtpEmailNormalizer(Options.Create(options)), clock);

        await svc.RequestAsync("user@example.com");
        var hashesAfterRequest = spyHasher.HashCallCount; // hashing the issued code

        var oversized = new string('9', 65); // > MaxCodeInputLength (64)
        var result = await svc.VerifyAsync("user@example.com", oversized);

        Assert.False(result.Succeeded);
        Assert.Equal(EmailOtpFailureReason.CodeMismatch, result.FailureReason);
        Assert.Equal(hashesAfterRequest, spyHasher.HashCallCount); // the oversized code was never hashed
    }

    [Fact]
    public async Task Oversized_email_is_rejected_before_persistence()
    {
        var h = Build(["123456"]);
        var longEmail = new string('a', EmailOtpSchema.EmailColumnLength) + "@x.com"; // > 320

        await Assert.ThrowsAsync<ArgumentException>(() => h.Service.RequestAsync(longEmail));
        Assert.Empty(h.Store.All()); // nothing was persisted
    }

    [Fact]
    public async Task Oversized_purpose_is_rejected_before_persistence()
    {
        var h = Build(["123456"]);
        var longPurpose = new string('p', EmailOtpSchema.PurposeColumnLength + 1);

        await Assert.ThrowsAsync<ArgumentException>(
            () => h.Service.RequestAsync("user@example.com", longPurpose));
        Assert.Empty(h.Store.All());
    }

    [Fact]
    public void Options_validate_rejects_short_secret()
    {
        var options = new EmailOtpOptions { Secret = "tooshort" };
        Assert.Throws<InvalidOperationException>(() => options.Validate());
    }

    [Fact]
    public void Options_validate_rejects_lengths_above_schema_columns()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new EmailOtpOptions { Secret = Pepper, MaxEmailLength = EmailOtpSchema.EmailColumnLength + 1 }.Validate());
        Assert.Throws<InvalidOperationException>(() =>
            new EmailOtpOptions { Secret = Pepper, MaxPurposeLength = EmailOtpSchema.PurposeColumnLength + 1 }.Validate());
    }
}
