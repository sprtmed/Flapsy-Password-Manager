import Foundation

struct VaultData: Codable {
    var items: [VaultItem]
    var categories: [VaultCategory]
    var settings: VaultSettings
    /// Standalone notes from the Notes mini-app. Separate from `VaultItem.noteText`
    /// (which is a per-item field on saved logins/cards/secure-notes).
    var notes: [Note]
    /// Tags for the Notes app (Private, Work, …). Separate from `categories`,
    /// which tag vault items.
    var noteTags: [VaultCategory]

    /// Internal schema revision for forward-compatible vault decoding.
    /// Increment when adding new Codable fields to prevent migration issues.
    static let schemaRevision: UInt16 = 6

    static var empty: VaultData {
        VaultData(
            items: [],
            categories: [],
            settings: VaultSettings.defaults,
            notes: [],
            noteTags: []
        )
    }

    init(items: [VaultItem], categories: [VaultCategory], settings: VaultSettings, notes: [Note] = [], noteTags: [VaultCategory] = []) {
        self.items = items
        self.categories = categories
        self.settings = settings
        self.notes = notes
        self.noteTags = noteTags
    }

    // Custom decoder so vaults written before the Notes feature (which have no
    // `notes` key) still decode. Mirrors the `decodeIfPresent` pattern used by
    // VaultSettings. The encoder remains the synthesized one.
    enum CodingKeys: String, CodingKey {
        case items, categories, settings, notes, noteTags
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        items = try container.decode([VaultItem].self, forKey: .items)
        categories = try container.decode([VaultCategory].self, forKey: .categories)
        settings = try container.decode(VaultSettings.self, forKey: .settings)
        notes = try container.decodeIfPresent([Note].self, forKey: .notes) ?? []
        noteTags = try container.decodeIfPresent([VaultCategory].self, forKey: .noteTags) ?? []
    }
}
