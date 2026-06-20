import Foundation
import SwiftUI
import Combine

final class SettingsViewModel: ObservableObject {
    @Published var theme: String = "dark" {
        didSet { NotificationCenter.default.post(name: .menuBarIconChanged, object: nil) }
    }
    @Published var menuBarIcon: String = "lock-shield" {
        didSet { NotificationCenter.default.post(name: .menuBarIconChanged, object: nil) }
    }
    @Published var menuBarShowLabel: Bool = true {
        didSet { NotificationCenter.default.post(name: .menuBarIconChanged, object: nil) }
    }
    @Published var menuBarLabel: String = "Vault" {
        didSet { NotificationCenter.default.post(name: .menuBarIconChanged, object: nil) }
    }
    @Published var autoLockEnabled: Bool = true
    @Published var autoLockMinutes: Double = 5
    @Published var clipboardClearEnabled: Bool = true
    @Published var clipboardClearSeconds: Double = 30
    @Published var biometricEnabled: Bool = false
    @Published var defaultFavoritesFilter: Bool = false
    @Published var confirmBeforeDelete: Bool = true
    @Published var checkForUpdates: Bool = true {
        didSet { UpdateCheckService.isEnabled = checkForUpdates }
    }
    @Published var keepWindowOpen: Bool = false
    @Published var openURLCopyPassword: Bool = false
    @Published var breachCheckEnabled: Bool = false
    @Published var alwaysExpandNotes: Bool = false
    @Published var defaultSortOption: SortOption = .newestFirst
    @Published var showNotesInTopBar: Bool = false
    @Published var showTodoInTopBar: Bool = false
    @Published var showPomodoroInTopBar: Bool = false
    @Published var requireAuthToEdit: Bool = false
    @Published var lastBackupDate: Date? = nil

    // Runtime-only: current pin state for this session (not persisted)
    @Published var isWindowPinned: Bool = false

    // Import/Export feedback
    @Published var showImportSuccess: Bool = false
    @Published var showExportSuccess: Bool = false

    var isDarkMode: Bool {
        theme == "dark"
    }

    func toggleTheme() {
        theme = isDarkMode ? "light" : "dark"
    }

    func selectMenuBarIcon(_ option: MenuBarIconOption) {
        menuBarIcon = option.id
        menuBarShowLabel = option.showLabel
        menuBarLabel = option.label
    }

    func loadFromVaultSettings(_ settings: VaultSettings) {
        theme = settings.theme
        menuBarIcon = settings.menuBarIcon
        menuBarShowLabel = settings.menuBarShowLabel
        menuBarLabel = settings.menuBarLabel
        autoLockEnabled = settings.autoLockEnabled
        autoLockMinutes = Double(settings.autoLockMinutes)
        clipboardClearEnabled = settings.clipboardClearEnabled
        clipboardClearSeconds = Double(settings.clipboardClearSeconds)
        biometricEnabled = settings.biometricEnabled
        defaultFavoritesFilter = settings.defaultFavoritesFilter
        confirmBeforeDelete = settings.confirmBeforeDelete
        checkForUpdates = settings.checkForUpdates
        keepWindowOpen = settings.keepWindowOpen
        isWindowPinned = settings.keepWindowOpen
        openURLCopyPassword = settings.openURLCopyPassword
        breachCheckEnabled = settings.breachCheckEnabled
        alwaysExpandNotes = settings.alwaysExpandNotes
        defaultSortOption = SortOption(rawValue: settings.defaultSortOption) ?? .newestFirst
        showNotesInTopBar = settings.showNotesInTopBar
        showTodoInTopBar = settings.showTodoInTopBar
        showPomodoroInTopBar = settings.showPomodoroInTopBar
        requireAuthToEdit = settings.requireAuthToEdit
        lastBackupDate = settings.lastBackupDate
    }

    func resetToDefaults() {
        theme = "dark"
        menuBarIcon = "lock-shield"
        menuBarShowLabel = true
        menuBarLabel = "Vault"
        autoLockEnabled = true
        autoLockMinutes = 5
        clipboardClearEnabled = true
        clipboardClearSeconds = 30
        biometricEnabled = false
        defaultFavoritesFilter = false
        confirmBeforeDelete = true
        checkForUpdates = true
        keepWindowOpen = false
        isWindowPinned = false
        openURLCopyPassword = false
        breachCheckEnabled = false
        alwaysExpandNotes = false
        defaultSortOption = .newestFirst
        showNotesInTopBar = false
        showTodoInTopBar = false
        showPomodoroInTopBar = false
        requireAuthToEdit = false
        // lastBackupDate intentionally not reset
    }

    func toVaultSettings() -> VaultSettings {
        VaultSettings(
            menuBarIcon: menuBarIcon,
            menuBarShowLabel: menuBarShowLabel,
            menuBarLabel: menuBarLabel,
            autoLockEnabled: autoLockEnabled,
            autoLockMinutes: Int(autoLockMinutes),
            clipboardClearEnabled: clipboardClearEnabled,
            clipboardClearSeconds: Int(clipboardClearSeconds),
            theme: theme,
            biometricEnabled: biometricEnabled,
            defaultFavoritesFilter: defaultFavoritesFilter,
            confirmBeforeDelete: confirmBeforeDelete,
            checkForUpdates: checkForUpdates,
            keepWindowOpen: keepWindowOpen,
            openURLCopyPassword: openURLCopyPassword,
            breachCheckEnabled: breachCheckEnabled,
            alwaysExpandNotes: alwaysExpandNotes,
            defaultSortOption: defaultSortOption.rawValue,
            showNotesInTopBar: showNotesInTopBar,
            showTodoInTopBar: showTodoInTopBar,
            showPomodoroInTopBar: showPomodoroInTopBar,
            requireAuthToEdit: requireAuthToEdit,
            lastBackupDate: lastBackupDate
        )
    }
}
