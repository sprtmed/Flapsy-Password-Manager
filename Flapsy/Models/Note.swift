import Foundation

/// A standalone, free-form note in the Notes mini-app.
///
/// Notes are NOT vault items — they have no category, type, URL, or password.
/// They live in their own `notes` array inside `VaultData` and inherit the same
/// Argon2id → AES-256-GCM encryption-at-rest as the rest of the vault.
///
/// There is no separate title field: the list label is derived from the first
/// non-empty line of `body`, mirroring the user's long-time Notational-Velocity
/// style workflow.
struct Note: Codable, Identifiable {
    let id: UUID
    var body: String
    var createdAt: Date
    var modifiedAt: Date

    init(id: UUID = UUID(), body: String = "", createdAt: Date = Date(), modifiedAt: Date = Date()) {
        self.id = id
        self.body = body
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
    }

    /// First non-empty line of the note, trimmed. Used as the list label.
    /// The row truncates this visually with `.lineLimit(1)`, so we keep the
    /// whole line here rather than hard-capping the word count.
    var displayTitle: String {
        let firstLine = body
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first(where: { !$0.isEmpty }) ?? ""
        return firstLine.isEmpty ? "New Note" : firstLine
    }

    /// A short one-line preview of the body after the title line (like the
    /// secondary text in the user's old notes app). Empty when there's nothing
    /// beyond the first line.
    var previewSubtitle: String {
        let lines = body
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard let firstIdx = lines.firstIndex(where: { !$0.isEmpty }) else { return "" }
        let rest = lines[(firstIdx + 1)...].first(where: { !$0.isEmpty }) ?? ""
        return String(rest.prefix(80))
    }

    /// `true` when the note has no meaningful content (used to discard blank
    /// notes the user opened but never typed into).
    var isEffectivelyEmpty: Bool {
        body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Relative-then-absolute date label, matching the user's reference app:
    /// "a moment ago", "3 days ago", then "2 June" for older notes.
    var dateDisplay: String {
        let interval = Date().timeIntervalSince(modifiedAt)
        let minutes = Int(interval / 60)
        if minutes < 1 { return "a moment ago" }
        if minutes < 60 { return "\(minutes) min ago" }
        let hours = minutes / 60
        if hours < 24 { return "\(hours) hr ago" }
        let days = hours / 24
        if days < 7 { return "\(days) day\(days == 1 ? "" : "s") ago" }

        let formatter = DateFormatter()
        let calendar = Calendar.current
        // Same calendar year → "2 June"; otherwise include the year.
        if calendar.isDate(modifiedAt, equalTo: Date(), toGranularity: .year) {
            formatter.dateFormat = "d MMMM"
        } else {
            formatter.dateFormat = "d MMM yyyy"
        }
        return formatter.string(from: modifiedAt)
    }
}
