import Foundation

struct MenuBarIconOption: Identifiable {
    let id: String
    let sfSymbol: String
    let showLabel: Bool
    let label: String

    static let allOptions: [MenuBarIconOption] = [
        MenuBarIconOption(id: "lock-shield", sfSymbol: "lock.shield.fill", showLabel: false, label: ""),
        MenuBarIconOption(id: "key", sfSymbol: "key.fill", showLabel: false, label: ""),
        MenuBarIconOption(id: "shield", sfSymbol: "shield.lefthalf.filled", showLabel: false, label: ""),
        MenuBarIconOption(id: "lock", sfSymbol: "lock.fill", showLabel: false, label: ""),
    ]
}

struct VaultSettings: Codable {
    var menuBarIcon: String
    var menuBarShowLabel: Bool
    var menuBarLabel: String
    var autoLockEnabled: Bool
    var autoLockMinutes: Int
    var clipboardClearEnabled: Bool
    var clipboardClearSeconds: Int
    var theme: String // "dark" or "light"
    var biometricEnabled: Bool
    var defaultFavoritesFilter: Bool
    var confirmBeforeDelete: Bool
    var checkForUpdates: Bool
    var keepWindowOpen: Bool
    var openURLCopyPassword: Bool
    var breachCheckEnabled: Bool
    var alwaysExpandNotes: Bool
    var defaultSortOption: String
    /// Show Notes / To-Do as their own icon in the top nav (vs. under the … menu).
    var showNotesInTopBar: Bool
    var showTodoInTopBar: Bool
    var lastBackupDate: Date?

    static var defaults: VaultSettings {
        VaultSettings(
            menuBarIcon: "lock-shield",
            menuBarShowLabel: true,
            menuBarLabel: "Vault",
            autoLockEnabled: true,
            autoLockMinutes: 5,
            clipboardClearEnabled: true,
            clipboardClearSeconds: 30,
            theme: "dark",
            biometricEnabled: false,
            defaultFavoritesFilter: false,
            confirmBeforeDelete: true,
            checkForUpdates: true,
            keepWindowOpen: false,
            openURLCopyPassword: false,
            breachCheckEnabled: false,
            alwaysExpandNotes: false,
            defaultSortOption: "Newest",
            showNotesInTopBar: false,
            showTodoInTopBar: false
        )
    }

    // Custom decoding to handle existing vaults that lack biometricEnabled
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        menuBarIcon = try container.decode(String.self, forKey: .menuBarIcon)
        menuBarShowLabel = try container.decode(Bool.self, forKey: .menuBarShowLabel)
        menuBarLabel = try container.decode(String.self, forKey: .menuBarLabel)
        autoLockEnabled = try container.decode(Bool.self, forKey: .autoLockEnabled)
        autoLockMinutes = try container.decode(Int.self, forKey: .autoLockMinutes)
        clipboardClearEnabled = try container.decode(Bool.self, forKey: .clipboardClearEnabled)
        clipboardClearSeconds = try container.decode(Int.self, forKey: .clipboardClearSeconds)
        theme = try container.decode(String.self, forKey: .theme)
        biometricEnabled = try container.decodeIfPresent(Bool.self, forKey: .biometricEnabled) ?? false
        defaultFavoritesFilter = try container.decodeIfPresent(Bool.self, forKey: .defaultFavoritesFilter) ?? false
        confirmBeforeDelete = try container.decodeIfPresent(Bool.self, forKey: .confirmBeforeDelete) ?? true
        checkForUpdates = try container.decodeIfPresent(Bool.self, forKey: .checkForUpdates) ?? true
        keepWindowOpen = try container.decodeIfPresent(Bool.self, forKey: .keepWindowOpen) ?? false
        openURLCopyPassword = try container.decodeIfPresent(Bool.self, forKey: .openURLCopyPassword) ?? false
        breachCheckEnabled = try container.decodeIfPresent(Bool.self, forKey: .breachCheckEnabled) ?? false
        alwaysExpandNotes = try container.decodeIfPresent(Bool.self, forKey: .alwaysExpandNotes) ?? false
        defaultSortOption = try container.decodeIfPresent(String.self, forKey: .defaultSortOption) ?? "Newest"
        showNotesInTopBar = try container.decodeIfPresent(Bool.self, forKey: .showNotesInTopBar) ?? false
        showTodoInTopBar = try container.decodeIfPresent(Bool.self, forKey: .showTodoInTopBar) ?? false
        lastBackupDate = try container.decodeIfPresent(Date.self, forKey: .lastBackupDate)
    }

    init(menuBarIcon: String, menuBarShowLabel: Bool, menuBarLabel: String,
         autoLockEnabled: Bool, autoLockMinutes: Int,
         clipboardClearEnabled: Bool, clipboardClearSeconds: Int,
         theme: String, biometricEnabled: Bool = false,
         defaultFavoritesFilter: Bool = false,
         confirmBeforeDelete: Bool = true,
         checkForUpdates: Bool = true,
         keepWindowOpen: Bool = false,
         openURLCopyPassword: Bool = false,
         breachCheckEnabled: Bool = false,
         alwaysExpandNotes: Bool = false,
         defaultSortOption: String = "Newest",
         showNotesInTopBar: Bool = false,
         showTodoInTopBar: Bool = false,
         lastBackupDate: Date? = nil) {
        self.menuBarIcon = menuBarIcon
        self.menuBarShowLabel = menuBarShowLabel
        self.menuBarLabel = menuBarLabel
        self.autoLockEnabled = autoLockEnabled
        self.autoLockMinutes = autoLockMinutes
        self.clipboardClearEnabled = clipboardClearEnabled
        self.clipboardClearSeconds = clipboardClearSeconds
        self.theme = theme
        self.biometricEnabled = biometricEnabled
        self.defaultFavoritesFilter = defaultFavoritesFilter
        self.confirmBeforeDelete = confirmBeforeDelete
        self.checkForUpdates = checkForUpdates
        self.keepWindowOpen = keepWindowOpen
        self.openURLCopyPassword = openURLCopyPassword
        self.breachCheckEnabled = breachCheckEnabled
        self.alwaysExpandNotes = alwaysExpandNotes
        self.defaultSortOption = defaultSortOption
        self.showNotesInTopBar = showNotesInTopBar
        self.showTodoInTopBar = showTodoInTopBar
        self.lastBackupDate = lastBackupDate
    }
}
