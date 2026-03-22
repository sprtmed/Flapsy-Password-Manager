import Cocoa
import SwiftUI
import Combine
import Carbon.HIToolbox

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var window: NSWindow!
    private var eventMonitor: Any?
    private var localKeyMonitor: Any?
    private var hotKeyRef: EventHotKeyRef?
    private var cancellables = Set<AnyCancellable>()

    // Shared state injected into SwiftUI
    let vaultViewModel = VaultViewModel()
    let settingsViewModel = SettingsViewModel()

    // Auto-lock service
    private let autoLockService = AutoLockService()

    // Update check service
    let updateCheckService = UpdateCheckService()

    func applicationDidFinishLaunching(_ notification: Notification) {
        AntiDebugService.denyDebuggerAttachment()

        // Wire VaultViewModel ↔ SettingsViewModel
        vaultViewModel.settingsViewModel = settingsViewModel

        setupStatusItem()
        setupWindow()
        setupEventMonitor()
        setupLocalKeyMonitor()
        registerGlobalHotKey()
        observeStateChanges()
        updateCheckService.checkForUpdate()
    }

    // MARK: - Observe ViewModel Changes

    private func observeStateChanges() {
        // Update menu bar icon when settings change
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(updateMenuBarIcon),
            name: .menuBarIconChanged,
            object: nil
        )

        // Start/stop auto-lock when vault lock state changes
        vaultViewModel.$isUnlocked
            .receive(on: RunLoop.main)
            .sink { [weak self] isUnlocked in
                guard let self = self else { return }
                if isUnlocked {
                    self.startAutoLockIfEnabled()
                } else {
                    self.autoLockService.stop()
                }
            }
            .store(in: &cancellables)

        // Update auto-lock timeout when settings change
        settingsViewModel.$autoLockMinutes
            .receive(on: RunLoop.main)
            .sink { [weak self] minutes in
                self?.autoLockService.updateTimeout(minutes: Int(minutes))
            }
            .store(in: &cancellables)

        settingsViewModel.$autoLockEnabled
            .receive(on: RunLoop.main)
            .sink { [weak self] enabled in
                guard let self = self else { return }
                if enabled && self.vaultViewModel.isUnlocked {
                    self.startAutoLockIfEnabled()
                } else if !enabled {
                    self.autoLockService.stop()
                }
            }
            .store(in: &cancellables)

        // Persist vault when settings change (theme, menu bar icon, etc.)
        Publishers.MergeMany(
            settingsViewModel.$theme.map { _ in () }.eraseToAnyPublisher(),
            settingsViewModel.$menuBarIcon.map { _ in () }.eraseToAnyPublisher(),
            settingsViewModel.$autoLockEnabled.map { _ in () }.eraseToAnyPublisher(),
            settingsViewModel.$clipboardClearEnabled.map { _ in () }.eraseToAnyPublisher(),
            settingsViewModel.$biometricEnabled.map { _ in () }.eraseToAnyPublisher(),
            settingsViewModel.$checkForUpdates.map { _ in () }.eraseToAnyPublisher(),
            settingsViewModel.$keepWindowOpen.map { _ in () }.eraseToAnyPublisher()
        )
        .dropFirst()
        .debounce(for: .milliseconds(500), scheduler: RunLoop.main)
        .sink { [weak self] _ in
            self?.vaultViewModel.persistVault()
        }
        .store(in: &cancellables)
    }

    private func startAutoLockIfEnabled() {
        guard settingsViewModel.autoLockEnabled else { return }
        autoLockService.start(
            lockAfterMinutes: Int(settingsViewModel.autoLockMinutes)
        ) { [weak self] in
            self?.vaultViewModel.lock()
        }
    }

    // MARK: - Status Item

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem.button {
            let config = NSImage.SymbolConfiguration(pointSize: 15, weight: .medium)
            let image = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: "Knox")
            button.image = image?.withSymbolConfiguration(config)
            button.image?.isTemplate = true
            button.imagePosition = .imageLeading
            button.action = #selector(toggleWindow)
            button.target = self
        }
    }

    @objc private func updateMenuBarIcon() {
        guard let button = statusItem.button else { return }

        let iconName = settingsViewModel.menuBarIcon
        let showLabel = settingsViewModel.menuBarShowLabel
        let label = settingsViewModel.menuBarLabel

        let option = MenuBarIconOption.allOptions.first { $0.id == iconName }
        let sfSymbol = option?.sfSymbol ?? "lock.shield.fill"

        let config = NSImage.SymbolConfiguration(pointSize: 15, weight: .medium)
        let image = NSImage(systemSymbolName: sfSymbol, accessibilityDescription: "Knox")
        button.image = image?.withSymbolConfiguration(config)
        button.image?.isTemplate = true

        if showLabel {
            button.title = " \(label)"
            button.imagePosition = .imageLeading
        } else {
            button.title = ""
            button.imagePosition = .imageOnly
        }
    }

    // MARK: - Window

    private func setupWindow() {
        let contentView = ContentView()
            .environmentObject(vaultViewModel)
            .environmentObject(settingsViewModel)
            .environmentObject(updateCheckService)

        let hostingController = NSHostingController(rootView: contentView)

        window = NSWindow(contentViewController: hostingController)
        window.styleMask = [.titled, .closable, .resizable, .fullSizeContentView]
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isMovableByWindowBackground = true
        window.level = .floating
        window.backgroundColor = .clear
        window.hasShadow = true
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 320, height: 480)
        window.maxSize = NSSize(width: 420, height: 650)
        window.setContentSize(NSSize(width: 420, height: 650))

        // Hide the traffic light buttons (close/minimize/zoom)
        window.standardWindowButton(.closeButton)?.isHidden = true
        window.standardWindowButton(.miniaturizeButton)?.isHidden = true
        window.standardWindowButton(.zoomButton)?.isHidden = true
    }

    @objc func toggleWindow() {
        if window.isVisible {
            window.orderOut(nil)
        } else {
            // Reset runtime pin state to the persisted default each time window opens
            settingsViewModel.isWindowPinned = settingsViewModel.keepWindowOpen
            positionWindowBelowStatusItem()
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)

            // Auto-focus search when vault is unlocked on the list panel
            if vaultViewModel.isUnlocked && vaultViewModel.currentPanel == .list {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
                    self?.vaultViewModel.isSearchFocused = true
                }
            }
        }
    }

    private func positionWindowBelowStatusItem() {
        guard let button = statusItem.button,
              let buttonWindow = button.window,
              let screen = buttonWindow.screen else { return }

        let buttonRect = buttonWindow.convertToScreen(button.convert(button.bounds, to: nil))
        let windowSize = window.frame.size

        // Center the window horizontally below the status item
        var x = buttonRect.midX - windowSize.width / 2
        let y = buttonRect.minY - windowSize.height - 4

        // Keep within screen bounds
        let screenFrame = screen.visibleFrame
        x = max(screenFrame.minX + 8, min(x, screenFrame.maxX - windowSize.width - 8))

        window.setFrameOrigin(NSPoint(x: x, y: y))
    }

    /// Validates that the window is still within visible screen bounds after
    /// display configuration changes (e.g., monitor disconnected).
    private func validateWindowPlacement() -> Bool {
        guard let screen = NSScreen.main else { return false }
        let frame = window.frame
        let visibleFrame = screen.visibleFrame
        let onScreen = frame.intersects(visibleFrame)
        if !onScreen { positionWindowBelowStatusItem() }
        return onScreen
    }

    // MARK: - Click Outside to Dismiss

    private func setupEventMonitor() {
        eventMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown]
        ) { [weak self] event in
            guard let self = self, self.window.isVisible else { return }

            // If pinned, don't dismiss on click-outside
            if self.settingsViewModel.isWindowPinned { return }

            // Don't dismiss if clicking the status bar button (toggle handles that)
            if let button = self.statusItem.button,
               let buttonWindow = button.window {
                let buttonRect = buttonWindow.convertToScreen(button.convert(button.bounds, to: nil))
                if buttonRect.contains(NSEvent.mouseLocation) { return }
            }

            self.window.orderOut(nil)
        }
    }

    private func setupLocalKeyMonitor() {
        localKeyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            guard let self = self else { return event }
            // Esc key dismisses the window (even when pinned)
            if event.keyCode == 53 && self.window.isVisible {
                self.window.orderOut(nil)
                return nil
            }
            return event
        }
    }

    // MARK: - Global Hotkey (⌘+Shift+P)

    private func registerGlobalHotKey() {
        var hotKeyID = EventHotKeyID()
        hotKeyID.signature = OSType(0x464C5059) // "FLPY"
        hotKeyID.id = 1

        let modifiers: UInt32 = UInt32(cmdKey | shiftKey)
        let keyCode: UInt32 = UInt32(kVK_ANSI_P)

        var eventType = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))

        InstallEventHandler(GetApplicationEventTarget(), { (_, event, userData) -> OSStatus in
            guard let userData = userData else { return OSStatus(eventNotHandledErr) }
            let delegate = Unmanaged<AppDelegate>.fromOpaque(userData).takeUnretainedValue()
            DispatchQueue.main.async {
                delegate.toggleWindow()
            }
            return noErr
        }, 1, &eventType, Unmanaged.passUnretained(self).toOpaque(), nil)

        RegisterEventHotKey(keyCode, modifiers, hotKeyID, GetApplicationEventTarget(), 0, &hotKeyRef)
    }

    // MARK: - Cleanup

    func applicationWillTerminate(_ notification: Notification) {
        // Save vault before quitting
        vaultViewModel.persistVault()

        // Wipe key from memory
        EncryptionService.shared.wipeKey()

        // Clean up monitors
        autoLockService.stop()
        if let monitor = eventMonitor {
            NSEvent.removeMonitor(monitor)
        }
        if let monitor = localKeyMonitor {
            NSEvent.removeMonitor(monitor)
        }
        if let hotKey = hotKeyRef {
            UnregisterEventHotKey(hotKey)
        }
    }
}

// MARK: - Notification Names

extension Notification.Name {
    static let menuBarIconChanged = Notification.Name("menuBarIconChanged")
}
