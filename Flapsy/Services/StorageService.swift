import Foundation
import CryptoKit
import os.log

private let logger = Logger(subsystem: "com.knox.app", category: "Storage")

/// Manages reading/writing the encrypted vault file to disk.
/// File location: ~/Library/Application Support/Knox/
final class StorageService {
    static let shared = StorageService()

    private let fileManager = FileManager.default
    private let encryption = EncryptionService.shared

    private init() {}

    // MARK: - Paths

    var appSupportDirectory: URL {
        let paths = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        let appSupport = paths[0].appendingPathComponent("Knox")
        try? fileManager.createDirectory(at: appSupport, withIntermediateDirectories: true)
        return appSupport
    }

    var vaultFileURL: URL {
        appSupportDirectory.appendingPathComponent("vault.enc")
    }

    var saltFileURL: URL {
        appSupportDirectory.appendingPathComponent("salt.dat")
    }

    var vaultBackupURL: URL {
        appSupportDirectory.appendingPathComponent("vault.enc.bak")
    }

    /// True if vault.enc exists on disk (regardless of salt or Keychain state).
    /// Use this to decide whether to show setup vs lock screen.
    var vaultFileExists: Bool {
        fileManager.fileExists(atPath: vaultFileURL.path)
    }

    /// True if the vault can be unlocked: vault.enc exists and salt is available
    /// (either from salt.dat or from the embedded vault header).
    var vaultExists: Bool {
        guard fileManager.fileExists(atPath: vaultFileURL.path) else { return false }
        return fileManager.fileExists(atPath: saltFileURL.path) || readEmbeddedSalt() != nil
    }

    /// For Settings display.
    var vaultFilePath: String {
        vaultFileURL.path.replacingOccurrences(of: NSHomeDirectory(), with: "~")
    }

    // MARK: - Salt
    // File format: [32-byte salt][32-byte SHA-256(salt)]  (64 bytes total)
    // Legacy format: [32-byte salt] (no checksum) — accepted and upgraded on next write.

    func readSalt() throws -> Data {
        guard fileManager.fileExists(atPath: saltFileURL.path) else {
            throw EncryptionError.saltMissing
        }
        let fileData = try Data(contentsOf: saltFileURL)

        if fileData.count == 32 {
            return fileData
        }

        guard fileData.count == 64 else {
            throw EncryptionError.saltCorrupted
        }

        let salt = fileData.prefix(32)
        let storedHash = fileData.suffix(32)
        let computedHash = Data(SHA256.hash(data: salt))

        guard storedHash == computedHash else {
            throw EncryptionError.saltCorrupted
        }

        return Data(salt)
    }

    func writeSalt(_ salt: Data) throws {
        let hash = Data(SHA256.hash(data: salt))
        var fileData = salt
        fileData.append(hash)
        try fileData.write(to: saltFileURL, options: [.atomic, .completeFileProtection])
        setOwnerOnly(saltFileURL)
    }

    func upgradeSaltIntegrityIfNeeded() {
        guard let fileData = try? Data(contentsOf: saltFileURL),
              fileData.count == 32 else { return }
        try? writeSalt(fileData)
    }

    /// Reads salt from salt.dat, falling back to the embedded vault header copy.
    func readSaltWithFallback() throws -> Data {
        do {
            return try readSalt()
        } catch {
            if let embeddedSalt = readEmbeddedSalt() {
                try? writeSalt(embeddedSalt)
                return embeddedSalt
            }
            throw error
        }
    }

    // MARK: - Vault File Format
    //
    // Version 1 (FLPV header):
    //   4 bytes: magic "FLPV"
    //   4 bytes: version UInt32 big-endian (1 = PBKDF2, 2 = Argon2id + Secret Key)
    //   32 bytes: redundant salt copy
    //   remaining: AES-256-GCM ciphertext
    //
    // Legacy (no header): raw AES-256-GCM ciphertext. Treated as version 1.

    private static let vaultMagic = "FLPV"
    private static let vaultHeaderSize = 4 + 4 + 32  // magic + version + salt = 40 bytes

    /// Reads the vault version from the file header.
    /// Returns .v1 for legacy files without a header.
    /// Throws for unrecognized version numbers to prevent silent misinterpretation.
    func readVaultVersion() throws -> VaultKeyVersion {
        guard let fileData = try? Data(contentsOf: vaultFileURL),
              fileData.count > StorageService.vaultHeaderSize else { return .v1 }
        let magic = String(data: fileData[0..<4], encoding: .ascii)
        guard magic == StorageService.vaultMagic else { return .v1 }  // legacy: no header
        let version = fileData[4..<8].withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard let knownVersion = VaultKeyVersion(rawValue: version) else {
            throw EncryptionError.unsupportedVaultVersion(version)
        }
        return knownVersion
    }

    /// Reads the encrypted payload from the vault file, stripping the header if present.
    /// For files with HMAC, the last 32 bytes are the HMAC tag and must be excluded.
    /// This method doesn't know if HMAC is present, so callers should use
    /// `decryptVaultWithIntegrity()` which handles both cases.
    func readEncryptedVaultData() throws -> Data {
        let fileData = try Data(contentsOf: vaultFileURL)
        return StorageService.stripVaultHeader(fileData)
    }

    /// Reads the raw vault file and returns both ciphertext variants for trial decryption:
    /// (withoutHMAC, withHMAC). Callers should try withoutHMAC first, then fall back to withHMAC.
    /// Used for password verification (re-auth, export, change password) where the standalone
    /// key can't use `decryptVaultWithIntegrity()`.
    func readEncryptedVaultDataForVerification() throws -> (primary: Data, fallback: Data) {
        let fileData = try Data(contentsOf: vaultFileURL)
        let full = StorageService.stripVaultHeader(fileData)

        let hasHeader = fileData.count > StorageService.vaultHeaderSize &&
            String(data: fileData[0..<4], encoding: .ascii) == StorageService.vaultMagic
        let hasPossibleHMAC = hasHeader &&
            fileData.count > StorageService.vaultHeaderSize + 28 + StorageService.hmacSize

        if hasPossibleHMAC {
            let payload = Data(fileData.prefix(fileData.count - StorageService.hmacSize))
            let withoutHMAC = StorageService.stripVaultHeader(payload)
            return (primary: withoutHMAC, fallback: full)
        }

        return (primary: full, fallback: full)
    }

    /// Decrypts the vault, automatically handling HMAC presence and verification.
    /// Tries decryption with HMAC stripped first (new format), falls back to full
    /// ciphertext (old format). Verifies HMAC if present.
    func decryptVaultWithIntegrity() throws -> VaultData {
        let fileData = try Data(contentsOf: vaultFileURL)
        let hasHeader = fileData.count > StorageService.vaultHeaderSize &&
            String(data: fileData[0..<4], encoding: .ascii) == StorageService.vaultMagic
        let hasPossibleHMAC = hasHeader &&
            fileData.count > StorageService.vaultHeaderSize + 28 + StorageService.hmacSize

        if hasPossibleHMAC {
            // Try with HMAC stripped
            let payload = Data(fileData.prefix(fileData.count - StorageService.hmacSize))
            let storedHMAC = Data(fileData.suffix(StorageService.hmacSize))
            let ciphertext = StorageService.stripVaultHeader(payload)

            if let vault = try? encryption.decryptVault(ciphertext) {
                // Decryption succeeded with HMAC stripped — verify HMAC
                if !encryption.verifyHMAC(over: payload, expected: storedHMAC) {
                    logger.error("Vault HMAC integrity check FAILED — possible corruption or tampering")
                    throw EncryptionError.integrityCheckFailed
                }
                return vault
            }
        }

        // Fall back: decrypt full ciphertext (pre-HMAC vault)
        let fullCiphertext = StorageService.stripVaultHeader(fileData)
        return try encryption.decryptVault(fullCiphertext)
    }

    /// Reads the embedded salt from the vault file header, if present.
    func readEmbeddedSalt() -> Data? {
        guard let fileData = try? Data(contentsOf: vaultFileURL),
              fileData.count > StorageService.vaultHeaderSize else { return nil }
        let magic = String(data: fileData[0..<4], encoding: .ascii)
        guard magic == StorageService.vaultMagic else { return nil }
        return Data(fileData[8..<40])
    }

    private static func stripVaultHeader(_ fileData: Data) -> Data {
        guard fileData.count > vaultHeaderSize else { return fileData }
        let magic = String(data: fileData[0..<4], encoding: .ascii)
        guard magic == vaultMagic else { return fileData }
        return Data(fileData[vaultHeaderSize...])
    }

    private static let hmacSize = 32  // SHA-256 output

    private func buildVaultFile(encrypted: Data, salt: Data, version: VaultKeyVersion) -> Data {
        var fileData = Data()
        fileData.append(StorageService.vaultMagic.data(using: .ascii)!)
        var ver = version.rawValue.bigEndian
        fileData.append(Data(bytes: &ver, count: 4))
        fileData.append(salt.prefix(32))
        fileData.append(encrypted)

        // Append HMAC-SHA256 integrity tag over the entire file contents
        if let hmac = encryption.computeHMAC(over: fileData) {
            fileData.append(hmac)
        }

        return fileData
    }

    /// Copies vault.enc → vault.enc.bak (single rolling backup).
    func backupVaultFile() {
        guard fileManager.fileExists(atPath: vaultFileURL.path) else { return }
        try? fileManager.removeItem(at: vaultBackupURL)
        try? fileManager.copyItem(at: vaultFileURL, to: vaultBackupURL)
        setOwnerOnly(vaultBackupURL)
    }

    func writeEncryptedVaultData(_ data: Data, salt: Data, version: VaultKeyVersion = .v2) throws {
        backupVaultFile()
        let fileData = buildVaultFile(encrypted: data, salt: salt, version: version)
        try fileData.write(to: vaultFileURL, options: [.atomic, .completeFileProtection])
        setOwnerOnly(vaultFileURL)
    }

    /// Sets file permissions to 0600 (owner read/write only).
    private func setOwnerOnly(_ url: URL) {
        do {
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            logger.warning("Failed to set 0600 on \(url.lastPathComponent, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - High-Level: Create New Vault (always v2)

    /// First-time setup: generates salt + Secret Key, derives key with Argon2id + HKDF,
    /// encrypts empty vault, writes to disk. Returns (VaultData, SecretKey).
    func createNewVault(masterPassword: String) throws -> (VaultData, Data) {
        let salt = encryption.generateSalt(byteCount: 32)
        try writeSalt(salt)

        // Generate and store Secret Key
        let secretKey = SecretKeyService.shared.generateSecretKey()
        guard SecretKeyService.shared.storeSecretKey(secretKey) else {
            throw EncryptionError.keyDerivationFailed
        }

        // Derive with v2 (Argon2id + HKDF + Secret Key)
        guard encryption.deriveKeyV2(from: masterPassword, salt: salt, secretKey: secretKey) != nil else {
            throw EncryptionError.keyDerivationFailed
        }

        let emptyVault = VaultData.empty
        let encrypted = try encryption.encryptVault(emptyVault)
        try writeEncryptedVaultData(encrypted, salt: salt, version: .v2)

        return (emptyVault, secretKey)
    }

    // MARK: - High-Level: Unlock Vault

    /// Reads vault version, salt, Secret Key; derives key with appropriate method; decrypts.
    /// On success the key stays in EncryptionService memory.
    /// Returns (VaultData, needsMigration). needsMigration is true for v1 vaults.
    func unlockVault(masterPassword: String) throws -> (VaultData, Bool) {
        let version = try readVaultVersion()
        let salt = try readSaltWithFallback()

        switch version {
        case .v1:
            // Legacy: PBKDF2 only
            guard encryption.deriveKeyV1(from: masterPassword, salt: salt) != nil else {
                throw EncryptionError.keyDerivationFailed
            }

            do {
                let encryptedData = try readEncryptedVaultData()
                let vault = try encryption.decryptVault(encryptedData)
                upgradeSaltIntegrityIfNeeded()
                return (vault, true)  // needs migration to v2
            } catch {
                encryption.wipeKey()
                throw EncryptionError.invalidPassword
            }

        case .v2:
            // Argon2id + HKDF + Secret Key
            guard let secretKey = SecretKeyService.shared.retrieveSecretKey() else {
                throw EncryptionError.secretKeyMissing
            }

            guard encryption.deriveKeyV2(from: masterPassword, salt: salt, secretKey: secretKey) != nil else {
                throw EncryptionError.keyDerivationFailed
            }

            do {
                let vault = try decryptVaultWithIntegrity()
                return (vault, false)
            } catch {
                encryption.wipeKey()
                throw error
            }
        }
    }

    // MARK: - Migration: Upgrade v1 → v2

    /// Re-encrypts the vault with Argon2id + Secret Key.
    /// Must be called while the vault is unlocked and the password is still available.
    /// Returns the newly generated Secret Key for display to the user.
    func migrateToV2(masterPassword: String, vault: VaultData) throws -> Data {
        let salt = encryption.generateSalt(byteCount: 32)
        try writeSalt(salt)

        let secretKey = SecretKeyService.shared.generateSecretKey()
        guard SecretKeyService.shared.storeSecretKey(secretKey) else {
            throw EncryptionError.keyDerivationFailed
        }

        guard encryption.deriveKeyV2(from: masterPassword, salt: salt, secretKey: secretKey) != nil else {
            throw EncryptionError.keyDerivationFailed
        }

        let encrypted = try encryption.encryptVault(vault)
        try writeEncryptedVaultData(encrypted, salt: salt, version: .v2)

        return secretKey
    }

    // MARK: - Unlock with Secret Key Recovery (v2 vault, no Keychain)

    /// Unlocks a v2 vault when the Secret Key was manually entered (recovery scenario).
    func unlockVault(masterPassword: String, recoveredSecretKey: Data) throws -> VaultData {
        let salt = try readSaltWithFallback()

        guard encryption.deriveKeyV2(from: masterPassword, salt: salt, secretKey: recoveredSecretKey) != nil else {
            throw EncryptionError.keyDerivationFailed
        }

        do {
            let vault = try decryptVaultWithIntegrity()
            // Re-store the recovered Secret Key in Keychain
            SecretKeyService.shared.storeSecretKey(recoveredSecretKey)
            return vault
        } catch {
            encryption.wipeKey()
            throw error
        }
    }

    // MARK: - Unlock with Pre-Derived Key (Touch ID)

    func unlockVault(withKeyData keyData: Data) throws -> VaultData {
        encryption.setKey(from: keyData)

        do {
            return try decryptVaultWithIntegrity()
        } catch {
            encryption.wipeKey()
            throw error
        }
    }

    // MARK: - High-Level: Save Vault

    func saveVault(_ vault: VaultData) throws {
        let encrypted = try encryption.encryptVault(vault)
        let salt = try readSalt()
        let version = try readVaultVersion()
        try writeEncryptedVaultData(encrypted, salt: salt, version: version)
    }

    // MARK: - High-Level: Lock

    func lockVault() {
        encryption.wipeKey()
    }

    // MARK: - Delete Vault (full reset)

    /// Removes ALL vault data: encrypted file, salt, backup, Secret Key, biometric key, and biometric flag.
    func deleteVaultFiles() {
        try? fileManager.removeItem(at: vaultFileURL)
        try? fileManager.removeItem(at: saltFileURL)
        try? fileManager.removeItem(at: vaultBackupURL)
        SecretKeyService.shared.deleteSecretKey()
        KeychainService.shared.deleteDerivedKey()
        KeychainService.biometricEnabledFlag = false
        encryption.wipeKey()
    }

    /// Reconciles partial writes that may occur if the process is terminated mid-save.
    /// Checks for temporary shard files and cleans up if the primary file is intact.
    private func reconcilePartialWrite() -> Bool {
        let tmpSuffix = ".vault-shard-pending"
        let contents = (try? fileManager.contentsOfDirectory(atPath: appSupportDirectory.path)) ?? []
        let shards = contents.filter { $0.hasSuffix(tmpSuffix) }
        guard !shards.isEmpty else { return false }
        for shard in shards {
            let shardURL = appSupportDirectory.appendingPathComponent(shard)
            try? fileManager.removeItem(at: shardURL)
        }
        logger.info("Cleaned \(shards.count, privacy: .public) orphaned vault shards")
        return true
    }

    /// Backs up the vault, then removes vault/salt/keys but preserves .bak.
    /// Used by "Start Fresh" so the user can manually recover the old vault.
    func deleteVaultFilesKeepingBackup() {
        backupVaultFile()
        try? fileManager.removeItem(at: vaultFileURL)
        try? fileManager.removeItem(at: saltFileURL)
        SecretKeyService.shared.deleteSecretKey()
        KeychainService.shared.deleteDerivedKey()
        KeychainService.biometricEnabledFlag = false
        encryption.wipeKey()
    }
}
