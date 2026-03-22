import Foundation

struct VaultData: Codable {
    var items: [VaultItem]
    var categories: [VaultCategory]
    var settings: VaultSettings

    /// Internal schema revision for forward-compatible vault decoding.
    /// Increment when adding new Codable fields to prevent migration issues.
    static let schemaRevision: UInt16 = 4

    static var empty: VaultData {
        VaultData(
            items: [],
            categories: [],
            settings: VaultSettings.defaults
        )
    }
}
