import Foundation

enum ItemType: String, Codable, CaseIterable {
    case login
    case card
    case note
}

struct PasswordHistoryEntry: Codable, Identifiable {
    let id: UUID
    let password: String
    let changedAt: Date

    init(password: String, changedAt: Date = Date()) {
        self.id = UUID()
        self.password = password
        self.changedAt = changedAt
    }
}

struct VaultItem: Codable, Identifiable {
    let id: UUID
    var type: ItemType
    var name: String
    var category: String
    var isFavorite: Bool
    var createdAt: Date
    var modifiedAt: Date

    // Login fields
    var url: String?
    var username: String?
    var password: String?
    var totpSecret: String?
    var loginNotes: String?

    // Card fields
    var cardType: String?
    var cardHolder: String?
    var cardNumber: String?
    var expiry: String?
    var cvv: String?
    var cardNotes: String?

    static let cardTypes = ["Visa", "Mastercard", "Amex", "Discover", "UnionPay"]

    // Note fields
    var noteText: String?

    // Password history (login items only)
    var previousPasswords: [PasswordHistoryEntry]?

    // Soft delete
    var deletedAt: Date?

    // Computed
    var subtitle: String {
        switch type {
        case .login:
            return username ?? ""
        case .card:
            return cardHolder ?? ""
        case .note:
            return String((noteText ?? "").prefix(40))
        }
    }

    var lastUsedDisplay: String {
        let interval = Date().timeIntervalSince(modifiedAt)
        let minutes = Int(interval / 60)
        if minutes < 1 { return "Just now" }
        if minutes < 60 { return "\(minutes) min ago" }
        let hours = minutes / 60
        if hours < 24 { return "\(hours) hr ago" }
        let days = hours / 24
        if days < 7 { return "\(days) day\(days == 1 ? "" : "s") ago" }
        let weeks = days / 7
        return "\(weeks) week\(weeks == 1 ? "" : "s") ago"
    }

    /// Number of days since the password was last changed (login items only).
    var passwordAgeDays: Int? {
        guard type == .login, password != nil, !password!.isEmpty else { return nil }
        return Int(Date().timeIntervalSince(modifiedAt) / 86400)
    }

    /// nil = fine (<90 days), "aging" = 90–179 days, "old" = 180+ days
    enum PasswordAge {
        case fresh, aging, old
    }

    var passwordAge: PasswordAge? {
        guard let days = passwordAgeDays else { return nil }
        if days >= 180 { return .old }
        if days >= 90 { return .aging }
        return .fresh
    }
}

extension VaultItem {
    /// Stable fingerprint for duplicate detection during import.
    /// Uses type prefix + a subset of fields to avoid false positives from metadata drift.
    var deduplicationKey: String {
        switch type {
        case .login:
            return "L:\(name.lowercased())|\(url?.lowercased() ?? "")|\(username?.lowercased() ?? "")"
        case .card:
            return "C:\(name.lowercased())|\(cardNumber?.suffix(4) ?? "")"
        case .note:
            return "N:\(name.lowercased())|\(String((noteText ?? "").prefix(64)).lowercased())"
        }
    }

    static func newLogin(name: String, url: String, username: String, password: String, category: String, totpSecret: String? = nil, loginNotes: String? = nil) -> VaultItem {
        VaultItem(
            id: UUID(), type: .login, name: name, category: category,
            isFavorite: false, createdAt: Date(), modifiedAt: Date(),
            url: url, username: username.isEmpty ? nil : username,
            password: password.isEmpty ? nil : password,
            totpSecret: totpSecret, loginNotes: loginNotes
        )
    }

    static func newCard(name: String, cardType: String, cardHolder: String, cardNumber: String, expiry: String, cvv: String, cardNotes: String, category: String) -> VaultItem {
        VaultItem(
            id: UUID(), type: .card, name: name, category: category,
            isFavorite: false, createdAt: Date(), modifiedAt: Date(),
            cardType: cardType.isEmpty ? nil : cardType,
            cardHolder: cardHolder, cardNumber: cardNumber, expiry: expiry, cvv: cvv,
            cardNotes: cardNotes.isEmpty ? nil : cardNotes
        )
    }

    static func newNote(name: String, noteText: String, category: String) -> VaultItem {
        VaultItem(
            id: UUID(), type: .note, name: name, category: category,
            isFavorite: false, createdAt: Date(), modifiedAt: Date(),
            noteText: noteText
        )
    }
}
