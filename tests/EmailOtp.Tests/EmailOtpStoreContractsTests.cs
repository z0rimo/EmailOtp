using EmailOtp;

namespace EmailOtp.Tests;

/// <summary>
/// Contract tests for <see cref="EmailOtpPendingChallenge"/> — the advanced store DTO. Pins the documented
/// hash-ownership semantics (defensive copy in and out) and input validation, so a custom hasher/store can
/// never corrupt a persisted hash or push an out-of-range value into the column.
/// </summary>
public class EmailOtpStoreContractsTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static EmailOtpPendingChallenge New(byte[] hash) =>
        new(Guid.NewGuid(), "user@example.com", EmailOtpPurposes.Login, hash, T0.AddMinutes(10), T0);

    [Fact]
    public void Mutating_the_source_array_after_construction_does_not_change_the_stored_hash()
    {
        var source = new byte[] { 1, 2, 3, 4 };
        var pending = New(source);

        source[0] = 0xFF; // caller reuses/scribbles its buffer after handing it over

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, pending.CodeHash); // unaffected — copied in
    }

    [Fact]
    public void Mutating_the_returned_hash_does_not_change_the_stored_hash()
    {
        var pending = New(new byte[] { 1, 2, 3, 4 });

        var read = pending.CodeHash;
        read[0] = 0xFF; // a store mutating what it read

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, pending.CodeHash); // each read is a fresh copy
    }

    [Fact]
    public void Null_hash_is_rejected()
    {
        Assert.Throws<ArgumentNullException>(() => New(null!));
    }

    [Fact]
    public void Empty_hash_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => New([]));
    }

    [Fact]
    public void Oversized_hash_is_rejected()
    {
        var tooBig = new byte[EmailOtpSchema.CodeHashColumnBytes + 1];
        Assert.Throws<ArgumentException>(() => New(tooBig));
    }

    [Fact]
    public void Hash_at_the_column_bound_is_accepted()
    {
        var atBound = new byte[EmailOtpSchema.CodeHashColumnBytes];
        var pending = New(atBound);
        Assert.Equal(EmailOtpSchema.CodeHashColumnBytes, pending.CodeHash.Length);
    }
}
