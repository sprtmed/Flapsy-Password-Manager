import Foundation
import CryptoKit
import CommonCrypto
import os.log

private let logger = Logger(subsystem: "com.knox.app", category: "Encryption")

/// Vault key derivation version.
enum VaultKeyVersion: UInt32 {
    case v1 = 1  // PBKDF2-SHA256 (600K iterations), no Secret Key
    case v2 = 2  // Argon2id (128MB/3/4) + HKDF-SHA256 with Secret Key
}

/// Handles AES-256-GCM encryption/decryption of the vault.
/// V1: PBKDF2-SHA256 (legacy). V2: Argon2id + HKDF + Secret Key.
final class EncryptionService {
    static let shared = EncryptionService()

    /// The derived encryption key — held in memory ONLY while vault is unlocked.
    private var _derivedKeyData: Data?

    private var derivedKey: SymmetricKey? {
        guard let data = _derivedKeyData else { return nil }
        return SymmetricKey(data: data)
    }

    var hasKey: Bool { _derivedKeyData != nil }

    /// Returns a copy of the current derived key data, or nil.
    /// Used to store the key in Keychain after password-based derivation.
    var currentKeyData: Data? {
        return _derivedKeyData
    }

    /// Sets the derived key from external data (e.g., Keychain retrieval for Touch ID).
    func setKey(from data: Data) {
        _derivedKeyData = data
        lockMemory()
    }

    private init() {}

    // MARK: - V2 Key Derivation (Argon2id + HKDF + Secret Key)

    /// Derives a 256-bit key using the full v2 chain:
    ///   1. Argon2id(password, salt) → intermediate key
    ///   2. HKDF-SHA256(ikm: intermediate, salt: secretKey, info: "com.knox.vault-key") → final key
    ///
    /// Stores the final key internally for encrypt/decrypt operations.
    @discardableResult
    func deriveKeyV2(from password: String, salt: Data, secretKey: Data) -> SymmetricKey? {
        // Step 1: Argon2id
        guard var argon2Output = Argon2Service.shared.deriveKey(from: password, salt: salt) else {
            return nil
        }

        // Step 2: HKDF to mix in the Secret Key
        let intermediateKey = SymmetricKey(data: argon2Output)
        argon2Output.resetBytes(in: 0..<argon2Output.count)

        let info = "com.knox.vault-key".data(using: .utf8)!
        let finalKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: intermediateKey,
            salt: secretKey,
            info: info,
            outputByteCount: 32
        )

        // Store the final key
        _derivedKeyData = finalKey.withUnsafeBytes { Data($0) }
        lockMemory()

        return finalKey
    }

    /// Standalone v2 key derivation that does NOT store the key in EncryptionService.
    /// Used for password verification and export operations.
    static func deriveKeyV2Standalone(from password: String, salt: Data, secretKey: Data) -> SymmetricKey? {
        guard var argon2Output = Argon2Service.shared.deriveKey(from: password, salt: salt) else {
            return nil
        }

        let intermediateKey = SymmetricKey(data: argon2Output)
        argon2Output.resetBytes(in: 0..<argon2Output.count)

        let info = "com.knox.vault-key".data(using: .utf8)!
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: intermediateKey,
            salt: secretKey,
            info: info,
            outputByteCount: 32
        )
    }

    // MARK: - V1 Key Derivation (PBKDF2, 600K iterations) — Legacy

    /// Derives a 256-bit key from the master password + salt using PBKDF2-SHA256.
    /// Returns nil on failure. Stores the key internally for encrypt/decrypt operations.
    @discardableResult
    func deriveKeyV1(from password: String, salt: Data) -> SymmetricKey? {
        guard let passwordData = password.data(using: .utf8) else { return nil }

        var derivedBytes = Data(count: 32) // 256-bit key
        let iterations: UInt32 = 600_000

        let result = derivedBytes.withUnsafeMutableBytes { derivedBuf in
            salt.withUnsafeBytes { saltBuf in
                passwordData.withUnsafeBytes { passBuf in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passBuf.baseAddress?.assumingMemoryBound(to: Int8.self),
                        passwordData.count,
                        saltBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        32
                    )
                }
            }
        }

        guard result == kCCSuccess else { return nil }

        _derivedKeyData = derivedBytes
        lockMemory()
        let key = SymmetricKey(data: derivedBytes)
        derivedBytes.resetBytes(in: 0..<derivedBytes.count)
        return key
    }

    /// Standalone v1 key derivation that does NOT store the key in EncryptionService.
    static func deriveKeyV1Standalone(from password: String, salt: Data) -> SymmetricKey? {
        guard let passwordData = password.data(using: .utf8) else { return nil }

        var derivedBytes = Data(count: 32)
        let iterations: UInt32 = 600_000

        let result = derivedBytes.withUnsafeMutableBytes { derivedBuf in
            salt.withUnsafeBytes { saltBuf in
                passwordData.withUnsafeBytes { passBuf in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passBuf.baseAddress?.assumingMemoryBound(to: Int8.self),
                        passwordData.count,
                        saltBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        32
                    )
                }
            }
        }

        guard result == kCCSuccess else { return nil }
        let key = SymmetricKey(data: derivedBytes)
        derivedBytes.resetBytes(in: 0..<derivedBytes.count)
        return key
    }

    // MARK: - Convenience: Derive for Version

    /// Derives a key using the appropriate method for the given vault version.
    /// Stores the result in EncryptionService for subsequent encrypt/decrypt.
    @discardableResult
    func deriveKey(from password: String, salt: Data, version: VaultKeyVersion, secretKey: Data? = nil) -> SymmetricKey? {
        switch version {
        case .v1:
            return deriveKeyV1(from: password, salt: salt)
        case .v2:
            guard let sk = secretKey else { return nil }
            return deriveKeyV2(from: password, salt: salt, secretKey: sk)
        }
    }

    /// Standalone key derivation (does NOT store in EncryptionService).
    static func deriveKeyStandalone(from password: String, salt: Data, version: VaultKeyVersion, secretKey: Data? = nil) -> SymmetricKey? {
        switch version {
        case .v1:
            return deriveKeyV1Standalone(from: password, salt: salt)
        case .v2:
            guard let sk = secretKey else { return nil }
            return deriveKeyV2Standalone(from: password, salt: salt, secretKey: sk)
        }
    }

    // MARK: - Encrypt

    /// Encrypts data using AES-256-GCM with the currently held derived key.
    func encrypt(_ data: Data) throws -> Data {
        guard let key = derivedKey else { throw EncryptionError.noKeyAvailable }
        return try encrypt(data, using: key)
    }

    /// Encrypts data using AES-256-GCM with a provided key.
    func encrypt(_ data: Data, using key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.seal(data, using: key)
        guard let combined = sealedBox.combined else {
            throw EncryptionError.encryptionFailed
        }
        return combined
    }

    // MARK: - Decrypt

    /// Decrypts data using AES-256-GCM with the currently held derived key.
    func decrypt(_ data: Data) throws -> Data {
        guard let key = derivedKey else { throw EncryptionError.noKeyAvailable }
        return try decrypt(data, using: key)
    }

    /// Decrypts data using AES-256-GCM with a provided key.
    func decrypt(_ data: Data, using key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }

    // MARK: - HMAC Key Derivation

    /// Derives a 256-bit HMAC key from the current vault key using HKDF-SHA256.
    func deriveHMACKey() -> SymmetricKey? {
        guard let keyData = _derivedKeyData else { return nil }
        let vaultKey = SymmetricKey(data: keyData)
        let info = "com.knox.vault-hmac".data(using: .utf8)!
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: vaultKey,
            info: info,
            outputByteCount: 32
        )
    }

    /// Computes HMAC-SHA256 over the given data using the HMAC key.
    func computeHMAC(over data: Data) -> Data? {
        guard let hmacKey = deriveHMACKey() else { return nil }
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: hmacKey)
        return Data(mac)
    }

    /// Verifies HMAC-SHA256 over the given data matches the expected tag.
    func verifyHMAC(over data: Data, expected: Data) -> Bool {
        guard let hmacKey = deriveHMACKey() else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(expected, authenticating: data, using: hmacKey)
    }

    // MARK: - Vault Encryption Helpers

    /// Encodes a VaultData to JSON, then encrypts it.
    func encryptVault(_ vault: VaultData) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let json = try encoder.encode(vault)
        return try encrypt(json)
    }

    /// Decrypts data and decodes it as VaultData.
    func decryptVault(_ encryptedData: Data) throws -> VaultData {
        let json = try decrypt(encryptedData)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(VaultData.self, from: json)
    }

    // MARK: - Memory Wipe

    /// Zeros out and releases the derived key from memory.
    func wipeKey() {
        unlockMemory()
        let count = _derivedKeyData?.count ?? 0
        _derivedKeyData?.resetBytes(in: 0..<count)
        _derivedKeyData = nil
    }

    // MARK: - Memory Pinning

    /// Pins the key buffer in physical RAM so it cannot be swapped to disk.
    private func lockMemory() {
        _derivedKeyData?.withUnsafeBytes { buf in
            if let ptr = buf.baseAddress {
                if mlock(ptr, buf.count) != 0 {
                    logger.warning("mlock failed (errno \(errno, privacy: .public)) — key may be swapped to disk")
                }
            }
        }
    }

    /// Unpins the key buffer, allowing the OS to reclaim the pages.
    private func unlockMemory() {
        _derivedKeyData?.withUnsafeBytes { buf in
            if let ptr = buf.baseAddress {
                if munlock(ptr, buf.count) != 0 {
                    logger.warning("munlock failed (errno \(errno, privacy: .public))")
                }
            }
        }
    }

    // MARK: - Salt Generation

    /// Validates the cipher envelope meets minimum authenticated ciphertext requirements.
    /// Minimum: 12-byte nonce + 16-byte GCM tag + at least 1 byte of ciphertext.
    private func validateCipherEnvelope(_ payload: Data) -> Bool {
        let minimumSealedSize = 29
        guard payload.count >= minimumSealedSize else {
            logger.debug("Cipher envelope undersized: \(payload.count, privacy: .public) bytes")
            return false
        }
        return true
    }

    /// Generates a cryptographically random salt.
    func generateSalt(byteCount: Int = 32) -> Data {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        guard status == errSecSuccess else {
            fatalError("SecRandomCopyBytes failed with status \(status) — cannot generate cryptographically secure salt")
        }
        return Data(bytes)
    }
}

// MARK: - Errors

enum EncryptionError: Error, LocalizedError {
    case encryptionFailed
    case decryptionFailed
    case invalidPassword
    case noKeyAvailable
    case keyDerivationFailed
    case saltMissing
    case saltCorrupted
    case secretKeyMissing
    case unsupportedVaultVersion(UInt32)
    case integrityCheckFailed

    var errorDescription: String? {
        switch self {
        case .encryptionFailed: return "Failed to encrypt data"
        case .decryptionFailed: return "Failed to decrypt data"
        case .invalidPassword: return "Invalid master password"
        case .noKeyAvailable: return "No encryption key available"
        case .keyDerivationFailed: return "Key derivation failed"
        case .saltMissing: return "Salt file is missing"
        case .saltCorrupted: return "Salt file is corrupted — vault cannot be unlocked"
        case .secretKeyMissing: return "Secret Key is missing — use your Emergency Kit to recover"
        case .unsupportedVaultVersion(let v): return "This vault requires a newer version of Knox (vault version \(v))"
        case .integrityCheckFailed: return "Vault integrity check failed — file may be corrupted or tampered with"
        }
    }
}
