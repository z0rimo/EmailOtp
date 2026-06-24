namespace EmailOtp;

/// <summary>
/// One-way hashing of codes. The built-in default is HMAC-SHA256 with a server-side pepper (32 bytes).
/// The store compares stored and candidate hashes in fixed time. A custom hasher must return, for a given
/// code, a stable, non-null, fixed-length byte array of 1..<see cref="EmailOtpSchema.CodeHashColumnBytes"/>
/// bytes. The library defensively copies the returned bytes, so a hasher may safely reuse its buffer.
/// </summary>
public interface IEmailOtpHasher
{
    /// <summary>Hashes a plaintext code to raw bytes.</summary>
    byte[] Hash(string code);
}
