import Foundation

struct VaultCategory: Codable, Identifiable {
    let id: UUID
    var key: String
    var label: String
    var color: String // Hex color (e.g. "3b82f6")

    static let availableColors: [String] = [
        "3b82f6", "8b5cf6", "10b981", "f59e0b", "ef4444",
        "ec4899", "06b6d4", "f97316", "6366f1", "84cc16",
        "14b8a6", "a855f7", "f43f5e", "0ea5e9", "d946ef",
        "eab308", "64748b", "78716c", "22d3ee", "fb923c"
    ]

    // MARK: - Migration from old format (icon + isDefault)

    private enum CodingKeys: String, CodingKey {
        case id, key, label, color, icon, isDefault
    }

    init(id: UUID = UUID(), key: String, label: String, color: String) {
        self.id = id
        self.key = key
        self.label = label
        self.color = color
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        key = try container.decode(String.self, forKey: .key)
        label = try container.decode(String.self, forKey: .label)

        // New format: has color
        if let color = try container.decodeIfPresent(String.self, forKey: .color) {
            self.color = color
        } else {
            // Migration: map old keys to colors
            switch key {
            case "dev": self.color = "3b82f6"       // blue
            case "personal": self.color = "8b5cf6"   // purple
            case "finance": self.color = "10b981"     // green
            case "entertainment": self.color = "f59e0b" // amber
            default: self.color = "f97316"            // orange fallback
            }
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(key, forKey: .key)
        try container.encode(label, forKey: .label)
        try container.encode(color, forKey: .color)
    }
}
