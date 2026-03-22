import Foundation
import AppKit
import CryptoKit
import UniformTypeIdentifiers

/// Handles importing vault data from 1Password, Bitwarden, Chrome, generic CSV, and Knox backup.
final class ImportService {
    static let shared = ImportService()

    private init() {}

    // MARK: - Types

    enum ImportFormat: String, CaseIterable {
        case onePasswordCSV = "1Password CSV"
        case bitwardenJSON  = "Bitwarden JSON"
        case bitwardenCSV   = "Bitwarden CSV"
        case chromeCSV      = "Chrome CSV"
        case genericCSV     = "Generic CSV"
        case knoxBackup     = "Knox Backup"
    }

    enum ImportError: Error, LocalizedError {
        case unsupportedFormat
        case parseError(String)
        case emptyFile
        case decryptionFailed
        case cancelled

        var errorDescription: String? {
            switch self {
            case .unsupportedFormat: return "Unsupported file format"
            case .parseError(let detail): return "Parse error: \(detail)"
            case .emptyFile: return "The file contains no data"
            case .decryptionFailed: return "Could not decrypt backup — wrong password?"
            case .cancelled: return "Import cancelled"
            }
        }
    }

    struct ImportResult {
        var items: [VaultItem] = []
        var format: ImportFormat = .genericCSV

        var loginCount: Int { items.filter { $0.type == .login }.count }
        var cardCount: Int { items.filter { $0.type == .card }.count }
        var noteCount: Int { items.filter { $0.type == .note }.count }
        var totalCount: Int { items.count }
    }

    // MARK: - Open Panel

    func showOpenPanel() -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Import Passwords"
        panel.message = "Select a file to import (CSV, JSON, or .knox backup)"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [
            .commaSeparatedText,
            .json,
            UTType(filenameExtension: "1pux") ?? .data,
            UTType(filenameExtension: "knox") ?? .data,
            .data
        ]

        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    // MARK: - Import

    /// Maximum import file size (256 MB). Prevents OOM on malicious or corrupt files.
    private static let maxImportFileSize: UInt64 = 256 * 1024 * 1024

    /// Auto-detects format and parses items from the file at `url`.
    /// For .knox backups, `password` must be provided to decrypt.
    /// Optional `progress` callback reports status strings (called from background thread).
    func importFromFile(_ url: URL, password: String? = nil, progress: ((String) -> Void)? = nil) throws -> ImportResult {
        // Check file size before loading into memory
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        let fileSize = attrs[.size] as? UInt64 ?? 0
        guard fileSize <= Self.maxImportFileSize else {
            throw ImportError.parseError("File is too large (\(fileSize / 1_048_576) MB, max 256 MB)")
        }

        let ext = url.pathExtension.lowercased()

        if ext == "knox" || ext == "flapsy" {
            guard let pw = password, !pw.isEmpty else {
                throw ImportError.parseError("Backup password is required")
            }
            return try importKnoxBackup(url, password: pw)
        }

        progress?("Reading file\u{2026}")
        let data = try Data(contentsOf: url)
        guard !data.isEmpty else { throw ImportError.emptyFile }

        if ext == "json" {
            progress?("Parsing JSON\u{2026}")
            let result = try importJSON(data)
            progress?("Parsed \(result.totalCount) items")
            return result
        }

        // CSV-based formats
        guard let text = String(data: data, encoding: .utf8) else {
            throw ImportError.parseError("Could not read file as text")
        }

        progress?("Parsing CSV\u{2026}")
        let rows = parseCSV(text)
        guard rows.count > 1 else { throw ImportError.emptyFile }

        let headers = rows[0].map { $0.lowercased().trimmingCharacters(in: .whitespaces) }
        let dataRows = Array(rows.dropFirst())

        let format = detectCSVFormat(headers: headers)
        progress?("Processing \(dataRows.count) rows\u{2026}")
        let items = parseCSVRows(dataRows, headers: headers, format: format, progress: progress)

        progress?("Parsed \(items.count) items")
        return ImportResult(items: items, format: format)
    }

    // MARK: - Format Detection

    private func detectCSVFormat(headers: [String]) -> ImportFormat {
        let headerSet = Set(headers)

        // 1Password CSV: "Title", "Url", "Username", "Password", "Notes", "Type"
        if headerSet.contains("title") && headerSet.contains("username") &&
           (headerSet.contains("url") || headerSet.contains("urls")) {
            return .onePasswordCSV
        }

        // Bitwarden CSV: "folder","favorite","type","name","notes","fields","reprompt","login_uri","login_username","login_password","login_totp"
        if headerSet.contains("login_uri") || headerSet.contains("login_username") {
            return .bitwardenCSV
        }

        // Chrome CSV: "name","url","username","password"
        if headers.count <= 5 && headerSet.contains("name") && headerSet.contains("url") &&
           headerSet.contains("username") && headerSet.contains("password") {
            return .chromeCSV
        }

        return .genericCSV
    }

    // MARK: - CSV Rows → VaultItems

    private func parseCSVRows(_ rows: [[String]], headers: [String], format: ImportFormat, progress: ((String) -> Void)? = nil) -> [VaultItem] {
        var items: [VaultItem] = []
        let total = rows.count
        // Report progress every 50 rows to avoid callback overhead
        let reportInterval = max(total / 20, 50)

        for (index, row) in rows.enumerated() {
            guard !row.allSatisfy({ $0.trimmingCharacters(in: .whitespaces).isEmpty }) else { continue }

            if progress != nil && (index % reportInterval == 0 || index == total - 1) {
                progress?("Parsing item \(index + 1) of \(total)\u{2026}")
            }

            let dict = rowToDict(row, headers: headers)

            switch format {
            case .onePasswordCSV:
                if let item = parse1PasswordRow(dict) { items.append(item) }
            case .bitwardenCSV:
                if let item = parseBitwardenCSVRow(dict) { items.append(item) }
            case .chromeCSV:
                if let item = parseChromeRow(dict) { items.append(item) }
            case .genericCSV:
                if let item = parseGenericRow(dict) { items.append(item) }
            default:
                break
            }
        }

        return items
    }

    private func rowToDict(_ row: [String], headers: [String]) -> [String: String] {
        var dict: [String: String] = [:]
        for (i, header) in headers.enumerated() {
            if i < row.count {
                dict[header] = row[i].trimmingCharacters(in: .whitespaces)
            }
        }
        return dict
    }

    // MARK: - 1Password CSV

    private func parse1PasswordRow(_ dict: [String: String]) -> VaultItem? {
        let name = dict["title"] ?? ""
        guard !name.isEmpty else { return nil }

        let typeStr = (dict["type"] ?? "login").lowercased()
        let notes = dict["notes"] ?? dict["notesplain"] ?? ""

        if typeStr.contains("credit card") || typeStr.contains("card") {
            let holder = dict["cardholder name"] ?? dict["cardholder"] ?? ""
            let number = dict["card number"] ?? dict["number"] ?? ""
            let exp = dict["expiry date"] ?? dict["expiry"] ?? ""
            let cvv = dict["verification number"] ?? dict["cvv"] ?? ""
            return .newCard(
                name: name,
                cardType: "",
                cardHolder: holder,
                cardNumber: number,
                expiry: exp,
                cvv: cvv,
                cardNotes: "",
                category: "finance"
            )
        }

        if typeStr.contains("note") || typeStr.contains("secure note") {
            return .newNote(name: name, noteText: notes, category: "personal")
        }

        // Default: login
        let url = dict["url"] ?? dict["urls"] ?? ""
        let username = dict["username"] ?? ""
        let password = dict["password"] ?? ""
        return .newLogin(
            name: name,
            url: url,
            username: username,
            password: password,
            category: "personal",
            loginNotes: notes.isEmpty ? nil : notes
        )
    }

    // MARK: - Bitwarden CSV

    private func parseBitwardenCSVRow(_ dict: [String: String]) -> VaultItem? {
        let name = dict["name"] ?? ""
        guard !name.isEmpty else { return nil }

        let typeStr = (dict["type"] ?? "1").lowercased()
        let notes = dict["notes"] ?? ""

        // Bitwarden types: 1=login, 2=note, 3=card, 4=identity
        if typeStr == "2" || typeStr == "note" {
            return .newNote(name: name, noteText: notes, category: "personal")
        }

        if typeStr == "3" || typeStr == "card" {
            let holder = dict["card_cardholdername"] ?? ""
            let number = dict["card_number"] ?? ""
            let cvv = dict["card_code"] ?? ""
            var expiry = ""
            if let m = dict["card_expmonth"], let y = dict["card_expyear"] {
                expiry = "\(m)/\(y.suffix(2))"
            }
            return .newCard(
                name: name,
                cardType: "",
                cardHolder: holder,
                cardNumber: number,
                expiry: expiry,
                cvv: cvv,
                cardNotes: "",
                category: "finance"
            )
        }

        // Default: login
        let loginUrl = dict["login_uri"] ?? ""
        let loginUser = dict["login_username"] ?? ""
        let loginPass = dict["login_password"] ?? ""
        return .newLogin(
            name: name,
            url: loginUrl,
            username: loginUser,
            password: loginPass,
            category: "personal",
            loginNotes: notes.isEmpty ? nil : notes
        )
    }

    // MARK: - Chrome CSV

    private func parseChromeRow(_ dict: [String: String]) -> VaultItem? {
        let name = dict["name"] ?? ""
        let url = dict["url"] ?? ""
        let username = dict["username"] ?? ""
        let password = dict["password"] ?? ""

        guard !name.isEmpty || !url.isEmpty else { return nil }

        return .newLogin(
            name: name.isEmpty ? domainFromURL(url) : name,
            url: url,
            username: username,
            password: password,
            category: "personal"
        )
    }

    // MARK: - Generic CSV (auto-detect columns)

    private func parseGenericRow(_ dict: [String: String]) -> VaultItem? {
        // Try to find name
        let name = dict["name"] ?? dict["title"] ?? dict["website"] ?? dict["site"] ?? dict["label"] ?? ""

        // Try to find URL
        let url = dict["url"] ?? dict["uri"] ?? dict["website"] ?? dict["site"] ?? dict["login_uri"] ?? ""

        // Try to find username
        let username = dict["username"] ?? dict["user"] ?? dict["email"] ?? dict["login"] ?? dict["login_username"] ?? ""

        // Try to find password
        let password = dict["password"] ?? dict["pass"] ?? dict["secret"] ?? dict["login_password"] ?? ""

        // Try to find notes
        let notes = dict["notes"] ?? dict["note"] ?? dict["extra"] ?? dict["comment"] ?? ""

        guard !name.isEmpty || !url.isEmpty || !username.isEmpty else { return nil }

        // If we have no password/username but have notes, treat as note
        if password.isEmpty && username.isEmpty && !notes.isEmpty {
            return .newNote(
                name: name.isEmpty ? "Imported Note" : name,
                noteText: notes,
                category: "personal"
            )
        }

        return .newLogin(
            name: name.isEmpty ? domainFromURL(url) : name,
            url: url,
            username: username,
            password: password,
            category: "personal",
            loginNotes: notes.isEmpty ? nil : notes
        )
    }

    // MARK: - Bitwarden JSON

    private func importJSON(_ data: Data) throws -> ImportResult {
        // Try Bitwarden JSON format
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ImportError.parseError("Invalid JSON structure")
        }

        // Bitwarden exports have "items" array
        guard let jsonItems = json["items"] as? [[String: Any]] else {
            throw ImportError.parseError("No 'items' array found in JSON")
        }

        var items: [VaultItem] = []

        for jsonItem in jsonItems {
            let name = jsonItem["name"] as? String ?? ""
            guard !name.isEmpty else { continue }

            let typeNum = jsonItem["type"] as? Int ?? 1
            let notes = jsonItem["notes"] as? String ?? ""

            switch typeNum {
            case 2: // Secure Note
                items.append(.newNote(name: name, noteText: notes, category: "personal"))

            case 3: // Card
                let card = jsonItem["card"] as? [String: Any]
                let expMonth = card?["expMonth"] as? String ?? ""
                let expYear = card?["expYear"] as? String ?? ""
                let expiry = !expMonth.isEmpty && !expYear.isEmpty
                    ? "\(expMonth)/\(expYear.suffix(2))"
                    : ""
                items.append(.newCard(
                    name: name,
                    cardType: "",
                    cardHolder: card?["cardholderName"] as? String ?? "",
                    cardNumber: card?["number"] as? String ?? "",
                    expiry: expiry,
                    cvv: card?["code"] as? String ?? "",
                    cardNotes: "",
                    category: "finance"
                ))

            default: // 1 = Login
                let login = jsonItem["login"] as? [String: Any]
                let uris = login?["uris"] as? [[String: Any]]
                let uri = uris?.first?["uri"] as? String ?? ""
                items.append(.newLogin(
                    name: name,
                    url: uri,
                    username: login?["username"] as? String ?? "",
                    password: login?["password"] as? String ?? "",
                    category: "personal",
                    loginNotes: notes.isEmpty ? nil : notes
                ))
            }
        }

        return ImportResult(items: items, format: .bitwardenJSON)
    }

    // MARK: - Knox Backup (.knox)

    /// Knox backup format:
    ///
    /// Version 1 (legacy):
    ///   4 bytes: magic "FLPY"
    ///   4 bytes: version (UInt32 big-endian, 1)
    ///   32 bytes: salt
    ///   remaining: AES-256-GCM encrypted VaultData JSON
    ///   Key: Argon2id(password, salt)
    ///
    /// Version 2:
    ///   4 bytes: magic "FLPY"
    ///   4 bytes: version (UInt32 big-endian, 2)
    ///   32 bytes: salt
    ///   16 bytes: backup Secret Key
    ///   remaining: AES-256-GCM encrypted VaultData JSON
    ///   Key: Argon2id(password, salt) → HKDF-SHA256(ikm, secretKey)
    ///
    /// Version 3 (password-only):
    ///   4 bytes: magic "FLPY"
    ///   4 bytes: version (UInt32 big-endian, 3)
    ///   32 bytes: salt
    ///   remaining: AES-256-GCM encrypted VaultData JSON
    ///   Key: Argon2id(password, salt)
    private func importKnoxBackup(_ url: URL, password: String) throws -> ImportResult {
        let data = try Data(contentsOf: url)
        guard data.count > 40 else { throw ImportError.parseError("File too small") }

        // Verify magic
        let magic = String(data: data[0..<4], encoding: .ascii)
        guard magic == "FLPY" else { throw ImportError.parseError("Not a valid Knox backup") }

        // Read version
        let version = data[4..<8].withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

        let key: SymmetricKey
        let encrypted: Data

        switch version {
        case 1, 3:
            // V1 (legacy) and V3 (password-only): Argon2id direct
            let salt = Data(data[8..<40])
            encrypted = Data(data[40...])
            guard let derivedKey = deriveKeyStandalone(from: password, salt: salt) else {
                throw ImportError.decryptionFailed
            }
            key = derivedKey

        case 2:
            // V2: Argon2id + HKDF with embedded Secret Key
            guard data.count > 56 else { throw ImportError.parseError("File too small for v2 backup") }
            let salt = Data(data[8..<40])
            let backupSecretKey = Data(data[40..<56])
            encrypted = Data(data[56...])
            guard let derivedKey = EncryptionService.deriveKeyV2Standalone(
                from: password, salt: salt, secretKey: backupSecretKey
            ) else {
                throw ImportError.decryptionFailed
            }
            key = derivedKey

        default:
            throw ImportError.parseError("Unsupported backup version \(version)")
        }

        // Decrypt
        let decrypted: Data
        do {
            decrypted = try EncryptionService.shared.decrypt(encrypted, using: key)
        } catch {
            throw ImportError.decryptionFailed
        }

        // Decode VaultData
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let vaultData: VaultData
        do {
            vaultData = try decoder.decode(VaultData.self, from: decrypted)
        } catch {
            throw ImportError.parseError("Could not decode backup data")
        }

        return ImportResult(items: vaultData.items, format: .knoxBackup)
    }

    // MARK: - Duplicate Detection

    /// Returns items from `incoming` that don't already exist in `existing`.
    /// Duplicates are matched by URL+username for logins, cardNumber for cards, name for notes.
    func deduplicateItems(incoming: [VaultItem], existing: [VaultItem]) -> [VaultItem] {
        let existingLogins = Set(
            existing.filter { $0.type == .login }
                .map { "\($0.url ?? "")|\($0.username ?? "")".lowercased() }
        )
        let existingCards = Set(
            existing.filter { $0.type == .card }
                .map { ($0.cardNumber ?? "").lowercased() }
        )
        let existingNotes = Set(
            existing.filter { $0.type == .note }
                .map { $0.name.lowercased() }
        )

        return incoming.filter { item in
            switch item.type {
            case .login:
                let key = "\(item.url ?? "")|\(item.username ?? "")".lowercased()
                return !existingLogins.contains(key)
            case .card:
                let key = (item.cardNumber ?? "").lowercased()
                return key.isEmpty || !existingCards.contains(key)
            case .note:
                return !existingNotes.contains(item.name.lowercased())
            }
        }
    }

    // MARK: - CSV Parser

    /// RFC 4180-compliant CSV parser. Handles quoted fields, embedded commas, newlines, escaped quotes.
    func parseCSV(_ text: String) -> [[String]] {
        var rows: [[String]] = []
        var currentRow: [String] = []
        var currentField = ""
        var inQuotes = false

        let chars = Array(text)
        var i = 0

        while i < chars.count {
            let c = chars[i]

            if inQuotes {
                if c == "\"" {
                    // Check for escaped quote ""
                    if i + 1 < chars.count && chars[i + 1] == "\"" {
                        currentField.append("\"")
                        i += 2
                    } else {
                        inQuotes = false
                        i += 1
                    }
                } else {
                    currentField.append(c)
                    i += 1
                }
            } else {
                if c == "\"" {
                    inQuotes = true
                    i += 1
                } else if c == "," {
                    currentRow.append(currentField)
                    currentField = ""
                    i += 1
                } else if c == "\r" {
                    // Handle \r\n or lone \r
                    currentRow.append(currentField)
                    currentField = ""
                    rows.append(currentRow)
                    currentRow = []
                    i += 1
                    if i < chars.count && chars[i] == "\n" { i += 1 }
                } else if c == "\n" {
                    currentRow.append(currentField)
                    currentField = ""
                    rows.append(currentRow)
                    currentRow = []
                    i += 1
                } else {
                    currentField.append(c)
                    i += 1
                }
            }
        }

        // Final field/row
        if !currentField.isEmpty || !currentRow.isEmpty {
            currentRow.append(currentField)
            rows.append(currentRow)
        }

        return rows
    }

    // MARK: - Encoding Detection

    /// Attempts to detect the character encoding of an import file by checking
    /// for BOM sequences and falling back to byte frequency analysis.
    private func detectEncoding(_ data: Data) -> String.Encoding {
        if data.count >= 3, data[0] == 0xEF, data[1] == 0xBB, data[2] == 0xBF {
            return .utf8
        }
        if data.count >= 2, data[0] == 0xFF, data[1] == 0xFE {
            return .utf16LittleEndian
        }
        if data.count >= 2, data[0] == 0xFE, data[1] == 0xFF {
            return .utf16BigEndian
        }
        let sampleSize = min(data.count, 4096)
        if sampleSize > 0 {
            let asciiCount = data.prefix(sampleSize).filter { $0 < 128 }.count
            if Double(asciiCount) / Double(sampleSize) > 0.92 {
                return .utf8
            }
        }
        return .windowsCP1252
    }

    // MARK: - Helpers

    private func domainFromURL(_ urlString: String) -> String {
        let cleaned = urlString
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
        return String(cleaned.prefix(while: { $0 != "/" }))
    }

    /// Standalone key derivation using Argon2id (doesn't store the key in EncryptionService).
    private func deriveKeyStandalone(from password: String, salt: Data) -> SymmetricKey? {
        guard var derivedBytes = Argon2Service.shared.deriveKey(from: password, salt: salt) else {
            return nil
        }
        let key = SymmetricKey(data: derivedBytes)
        derivedBytes.resetBytes(in: 0..<derivedBytes.count)
        return key
    }
}
