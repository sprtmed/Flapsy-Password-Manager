import Foundation
import Security
import CryptoKit

/// Manages a Secure Enclave-backed key that wraps/unwraps the vault Secret Key.
///
/// Instead of storing the raw 128-bit Secret Key in the Keychain (extractable),
/// we store it encrypted (wrapped) by a P-256 key that lives in the Secure Enclave.
/// The SE private key never leaves hardware — even root access can't extract it.
///
/// Flow:
///   1. Generate a P-256 key pair in the Secure Enclave (once)
///   2. Wrap the Secret Key: ECIES encrypt using the SE public key
///   3. Store the wrapped blob in the regular Keychain
///   4. Unwrap: SE decrypts the blob, returning the raw Secret Key
///
/// Falls back to regular Keychain storage on machines without Secure Enclave.
final class SecureEnclaveService {
    static let shared = SecureEnclaveService()

    private let seKeyTag = "com.knox.app.se-wrapping-key"
    private let wrappedAccount = "vault-secret-key-wrapped"
    private let service = "com.knox.app"

    private init() {}

    // MARK: - Availability

    var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    // MARK: - SE Key Management

    /// Returns the existing SE private key, or creates one if it doesn't exist.
    private func getOrCreateSEKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        // Try to load existing key
        if let existing = try? loadSEKey() {
            return existing
        }
        // Create new key in Secure Enclave
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        )!

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: accessControl
        )

        // Store the key's data representation so we can reload it
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: seKeyTag.data(using: .utf8)!,
            kSecValueData as String: key.dataRepresentation,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        // Delete any stale entry first
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SEError.keyStoreFailed
        }

        return key
    }

    private func loadSEKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: seKeyTag.data(using: .utf8)!,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }

        return try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: data
        )
    }

    // MARK: - Wrap / Unwrap Secret Key

    /// Wraps (encrypts) the Secret Key using the SE public key via ECIES.
    func wrapSecretKey(_ secretKey: Data) throws -> Data {
        guard isAvailable else { throw SEError.notAvailable }
        let seKey = try getOrCreateSEKey()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(
            with: seKey.publicKey
        )
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("com.knox.se-wrap".utf8),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        let sealed = try AES.GCM.seal(secretKey, using: symmetricKey)
        // Store: ephemeral public key (compressed) + sealed.combined
        var wrapped = Data()
        wrapped.append(ephemeral.publicKey.compressedRepresentation)
        wrapped.append(sealed.combined!)
        return wrapped
    }

    /// Unwraps (decrypts) the Secret Key using the SE private key.
    func unwrapSecretKey(_ wrappedData: Data) throws -> Data {
        guard isAvailable else { throw SEError.notAvailable }
        let seKey = try getOrCreateSEKey()

        // Parse: 33 bytes compressed public key + rest is sealed box
        guard wrappedData.count > 33 else { throw SEError.invalidWrappedData }
        let ephemeralPubKeyData = wrappedData.prefix(33)
        let sealedData = wrappedData.dropFirst(33)

        let ephemeralPubKey = try P256.KeyAgreement.PublicKey(
            compressedRepresentation: ephemeralPubKeyData
        )
        let sharedSecret = try seKey.sharedSecretFromKeyAgreement(
            with: ephemeralPubKey
        )
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("com.knox.se-wrap".utf8),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        let sealedBox = try AES.GCM.SealedBox(combined: sealedData)
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }

    // MARK: - Wrapped Key Keychain Storage

    /// Stores the wrapped Secret Key blob in the Keychain.
    @discardableResult
    func storeWrappedKey(_ wrappedData: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: wrappedAccount,
            kSecValueData as String: wrappedData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    /// Retrieves the wrapped Secret Key blob from the Keychain.
    func retrieveWrappedKey() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: wrappedAccount,
            kSecReturnData as String: true
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return data
    }

    /// True if a wrapped Secret Key exists in the Keychain.
    var hasWrappedKey: Bool {
        retrieveWrappedKey() != nil
    }

    /// Deletes the wrapped key and SE key from Keychain.
    func deleteAll() {
        let wrappedQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: wrappedAccount
        ]
        SecItemDelete(wrappedQuery as CFDictionary)

        let seQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: seKeyTag.data(using: .utf8)!
        ]
        SecItemDelete(seQuery as CFDictionary)
    }

    /// Rotates the SE wrapping key by generating a new P-256 key pair and
    /// re-wrapping the Secret Key. Intended for use if the existing key is
    /// suspected of compromise via hardware fault injection on older T1 chips.
    private func rotateWrappingKey() throws {
        guard isAvailable else { throw SEError.notAvailable }
        guard let currentSecret = retrieveSecretKey() else { return }
        let seQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: seKeyTag.data(using: .utf8)!
        ]
        SecItemDelete(seQuery as CFDictionary)
        let wrapped = try wrapSecretKey(currentSecret)
        storeWrappedKey(wrapped)
    }

    // MARK: - Migration

    /// Migrates a plain Secret Key (from SecretKeyService) to SE-wrapped storage.
    /// Returns true if migration succeeded, false if SE is unavailable or failed.
    @discardableResult
    func migrateFromPlainKey() -> Bool {
        guard isAvailable else { return false }
        guard let plainKey = SecretKeyService.shared.retrievePlainKey() else { return false }
        guard !hasWrappedKey else { return true } // already migrated

        do {
            let wrapped = try wrapSecretKey(plainKey)
            guard storeWrappedKey(wrapped) else { return false }
            // Verify we can unwrap before deleting plain key
            guard let unwrapped = try? unwrapSecretKey(wrapped), unwrapped == plainKey else {
                // Unwrap failed — keep plain key, remove broken wrapped key
                let deleteQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: wrappedAccount
                ]
                SecItemDelete(deleteQuery as CFDictionary)
                return false
            }
            // SE wrap verified — safe to remove the plain key
            SecretKeyService.shared.deletePlainKey()
            return true
        } catch {
            return false
        }
    }

    /// Retrieves the Secret Key, preferring SE-wrapped if available,
    /// falling back to plain Keychain storage.
    func retrieveSecretKey() -> Data? {
        // Try SE-wrapped first
        if let wrapped = retrieveWrappedKey() {
            if let unwrapped = try? unwrapSecretKey(wrapped) {
                return unwrapped
            }
        }
        // Fallback to plain key
        return SecretKeyService.shared.retrievePlainKey()
    }

    /// Stores a new Secret Key — uses SE wrapping if available, else plain Keychain.
    @discardableResult
    func storeSecretKey(_ keyData: Data) -> Bool {
        if isAvailable {
            do {
                let wrapped = try wrapSecretKey(keyData)
                return storeWrappedKey(wrapped)
            } catch {
                // Fallback to plain storage
                return SecretKeyService.shared.storePlainKey(keyData)
            }
        }
        return SecretKeyService.shared.storePlainKey(keyData)
    }

    // MARK: - Errors

    enum SEError: Error, LocalizedError {
        case notAvailable
        case keyStoreFailed
        case invalidWrappedData

        var errorDescription: String? {
            switch self {
            case .notAvailable: return "Secure Enclave not available"
            case .keyStoreFailed: return "Failed to store SE key"
            case .invalidWrappedData: return "Invalid wrapped key data"
            }
        }
    }
}
