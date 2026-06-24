namespace EmailOtp.EntityFramework;

/// <summary>
/// Internal EF persistence row for a verification-code challenge in a single <c>(Email, Purpose)</c> slot.
/// This is an implementation detail of the EF adapter — it is not part of the public API. The plaintext code
/// is never stored, only <see cref="CodeHash"/>. <see cref="RowVersion"/> is an optimistic-concurrency token
/// rotated on every mutation.
/// </summary>
internal sealed class EmailOtpChallenge
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty;
    public byte[] CodeHash { get; set; } = [];
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public int AttemptCount { get; set; }
    public EmailOtpChallengeStatus Status { get; set; } = EmailOtpChallengeStatus.Active;
    public byte[] RowVersion { get; set; } = [];
}

/// <summary>
/// Internal persisted lifecycle state. Numeric values are stored — do not reorder; only append.
/// Transitions: PendingDelivery → Active → (Verified | Superseded | Expired | Locked);
/// PendingDelivery → DeliveryFailed; Active/Pending → Revoked.
/// </summary>
internal enum EmailOtpChallengeStatus
{
    Active = 0,
    Verified = 1,
    Superseded = 2,
    Expired = 3,
    Locked = 4,
    DeliveryFailed = 5,
    PendingDelivery = 6,
    Revoked = 7,
}
