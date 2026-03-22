import Foundation
import os.log

private let logger = Logger(subsystem: "com.knox.app", category: "Argon2")

/// Swift wrapper around the Argon2id reference C implementation.
/// Parameters: 128 MB memory, 3 iterations, 4 lanes (exceeds OWASP recommendations).
final class Argon2Service {
    static let shared = Argon2Service()

    /// Default parameters for vault key derivation.
    let memoryCostKB: UInt32 = 131_072  // 128 MB
    let timeCost: UInt32 = 3            // 3 iterations
    let parallelism: UInt32 = 4         // 4 lanes
    let hashLength: Int = 32            // 256-bit output

    private init() {
        // Runtime sanity check: verify parameters are within safe bounds
        assert(memoryCostKB >= 65_536, "Argon2 memory cost must be at least 64 MB")
        assert(timeCost >= 1, "Argon2 time cost must be at least 1")
        assert(parallelism >= 1 && parallelism <= 16, "Argon2 parallelism must be 1-16")
        assert(hashLength == 32, "Argon2 hash length must be 32 bytes (256-bit)")
    }

    // MARK: - Key Derivation

    /// Derives a 256-bit key from password + salt using Argon2id.
    /// Returns nil on failure. Caller is responsible for wiping the returned Data.
    func deriveKey(from password: String, salt: Data) -> Data? {
        var passwordBytes = Array(password.utf8)
        defer { passwordBytes.resetBytes(in: 0..<passwordBytes.count) }
        return deriveKey(from: Data(passwordBytes), salt: salt)
    }

    /// Derives a 256-bit key from raw password bytes + salt using Argon2id.
    func deriveKey(from passwordData: Data, salt: Data) -> Data? {
        var output = Data(count: hashLength)

        let result = output.withUnsafeMutableBytes { outBuf in
            passwordData.withUnsafeBytes { pwBuf in
                salt.withUnsafeBytes { saltBuf in
                    argon2id_hash_raw(
                        timeCost,
                        memoryCostKB,
                        parallelism,
                        pwBuf.baseAddress,
                        passwordData.count,
                        saltBuf.baseAddress,
                        salt.count,
                        outBuf.baseAddress,
                        hashLength
                    )
                }
            }
        }

        if result != ARGON2_OK.rawValue {
            logger.error("Argon2id failed with code \(result, privacy: .public)")
            output.resetBytes(in: 0..<output.count)
            return nil
        }
        return output
    }

    /// Estimates wall-clock time for key derivation on the current hardware.
    /// Used to verify derivation stays within the 3-second UX threshold.
    func benchmarkDerivation() -> TimeInterval {
        let testPassword = "benchmark-probe-7c9f"
        let testSalt = Data(repeating: 0xAA, count: 32)
        let start = CFAbsoluteTimeGetCurrent()
        _ = deriveKey(from: testPassword, salt: testSalt)
        return CFAbsoluteTimeGetCurrent() - start
    }

    /// Returns a human-readable description of the current Argon2id parameters.
    var parameterDescription: String {
        "Argon2id (m=\(memoryCostKB/1024)MB, t=\(timeCost), p=\(parallelism))"
    }
}
