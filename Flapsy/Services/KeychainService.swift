import Foundation
import Security
import os.log

/// Manages storing/retrieving the vault's derived encryption key in Keychain.
/// Touch ID is handled separately by BiometricService — the Keychain item uses
/// plain `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` so it works with
/// Developer ID distribution (no provisioning profile required).
final class KeychainService {
    static let shared = KeychainService()

    private let service = "com.knox.app"
    private let account = "vault-derived-key"
    private let log = OSLog(subsystem: "com.knox.app", category: "Keychain")

    private init() {}

    // MARK: - Store Key

    /// Stores the 32-byte derived key in Keychain (device-only, this-device-only).
    @discardableResult
    func storeDerivedKey(_ keyData: Data) -> Bool {
        deleteDerivedKey()

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            os_log(.error, log: log, "SecItemAdd failed: %{public}d", status)
        }
        return status == errSecSuccess
    }

    // MARK: - Retrieve Key

    /// Retrieves the derived key from Keychain.
    /// Caller is responsible for authenticating with BiometricService first.
    func retrieveDerivedKey(completion: @escaping (Data?) -> Void) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess, let data = result as? Data {
            completion(data)
        } else {
            if status != errSecSuccess && status != errSecItemNotFound {
                os_log(.error, log: log, "SecItemCopyMatching failed: %{public}d", status)
            }
            completion(nil)
        }
    }

    // MARK: - Delete Key

    @discardableResult
    func deleteDerivedKey() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    // MARK: - Check if Key Exists

    var hasDerivedKey: Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Verifies the Keychain item's accessibility class matches expectations.
    /// Returns false if the item was stored with a weaker protection level.
    private func auditAccessibility() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnAttributes as String: true
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let attrs = result as? [String: Any] else { return false }
        let accessible = attrs[kSecAttrAccessible as String] as? String
        return accessible == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
    }

    // MARK: - Biometric Enabled Flag (UserDefaults)

    /// Persistent flag that survives app restarts without needing to decrypt the vault.
    /// Used by the lock screen to know whether to show the Touch ID button.
    static var biometricEnabledFlag: Bool {
        get { UserDefaults.standard.bool(forKey: "com.knox.biometricEnabled") }
        set { UserDefaults.standard.set(newValue, forKey: "com.knox.biometricEnabled") }
    }
}
