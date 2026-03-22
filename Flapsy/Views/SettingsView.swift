import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @EnvironmentObject var settings: SettingsViewModel
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                launchAtLoginSection
                themeToggle
                keepWindowOpenSection
                menuBarIconPicker
                autoLockSection
                touchIDSection
                clipboardSection
                openURLCopySection
                favoritesDefaultSection
                expandNotesSection
                deleteConfirmSection
                updateCheckSection
                breachCheckSection
                secretKeySection
                changePasswordSection
                backupReminder
                dataSection
                securityInfo
                vaultLocation
                dangerZoneSection
            }
            .padding(16)
        }
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }

    // MARK: - Launch at Login

    private var launchAtLoginSection: some View {
        VStack(spacing: 4) {
            HStack {
                HStack(spacing: 8) {
                    Image(systemName: "sunrise.fill")
                        .font(.system(size: 14))
                        .foregroundColor(theme.accentYellow)
                    Text("Launch at Login")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                }
                Spacer()
                FlapsyToggle(isOn: Binding(
                    get: { launchAtLogin },
                    set: { newValue in
                        do {
                            if newValue {
                                try SMAppService.mainApp.register()
                            } else {
                                try SMAppService.mainApp.unregister()
                            }
                            launchAtLogin = newValue
                        } catch {
                            launchAtLogin = SMAppService.mainApp.status == .enabled
                        }
                    }
                ))
            }
            .padding(.vertical, 4)
            Text("Automatically start Knox when you log in to your Mac.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(theme.textFaint)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Theme Toggle

    private var themeToggle: some View {
        HStack {
            HStack(spacing: 8) {
                Text(settings.isDarkMode ? "\u{1F319}" : "\u{2600}\u{FE0F}")
                    .font(.system(size: 16))
                Text(settings.isDarkMode ? "Dark Mode" : "Light Mode")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(theme.text)
            }
            Spacer()
            FlapsyToggle(
                isOn: Binding(
                    get: { !settings.isDarkMode },
                    set: { _ in settings.toggleTheme() }
                ),
                accentColor: Color(hex: "f59e0b")
            )
        }
    }

    // MARK: - Keep Window Open

    private var keepWindowOpenSection: some View {
        VStack(spacing: 4) {
            HStack {
                HStack(spacing: 8) {
                    Image(systemName: "pin.fill")
                        .font(.system(size: 14))
                        .foregroundColor(theme.accentYellow)
                    Text("Keep Window Open")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                }
                Spacer()
                FlapsyToggle(isOn: $settings.keepWindowOpen)
            }
            .padding(.vertical, 4)
            Text("Window stays visible when you click outside. Toggle per session with the pin button.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(theme.textFaint)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Menu Bar Icon Picker

    private var menuBarIconPicker: some View {
        VStack(alignment: .leading, spacing: 10) {
            FormLabel("MENU BAR ICON")
            HStack(spacing: 8) {
                ForEach(MenuBarIconOption.allOptions) { opt in
                    let isSelected = settings.menuBarIcon == opt.id
                    Button(action: { settings.selectMenuBarIcon(opt) }) {
                        Image(systemName: opt.sfSymbol)
                            .font(.system(size: 16, weight: .medium))
                            .foregroundColor(isSelected ? theme.accentBlueLt : theme.textSecondary)
                            .frame(maxWidth: .infinity)
                            .frame(height: 40)
                            .background(isSelected ? theme.activeBg : theme.fieldBg)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(
                                        isSelected ? theme.focusBorder : theme.inputBorder,
                                        lineWidth: 1
                                    )
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    // MARK: - Auto-Lock

    private var autoLockSection: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Auto-Lock")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(theme.text)
                Spacer()
                FlapsyToggle(isOn: $settings.autoLockEnabled)
            }
            .padding(.vertical, 10)

            if settings.autoLockEnabled {
                VStack(spacing: 6) {
                    HStack {
                        Text("Timer")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(theme.textFaint)
                        Spacer()
                        Text("\(Int(settings.autoLockMinutes)) min")
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                            .foregroundColor(theme.accentBlueLt)
                    }
                    Slider(value: $settings.autoLockMinutes, in: 1...30, step: 1)
                        .tint(theme.accentBlue)
                    HStack {
                        Text("1m")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundColor(theme.textGhost)
                        Spacer()
                        Text("30m")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundColor(theme.textGhost)
                    }
                }
                .padding(.leading, 4)
            }
        }
    }

    // MARK: - Touch ID

    private var touchIDSection: some View {
        VStack(spacing: 4) {
            HStack {
                HStack(spacing: 8) {
                    Image(systemName: "touchid")
                        .font(.system(size: 16))
                        .foregroundColor(theme.accentBlueLt)
                    Text("Touch ID")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                }
                Spacer()
                if BiometricService.shared.isBiometricAvailable {
                    FlapsyToggle(isOn: Binding(
                        get: { settings.biometricEnabled },
                        set: { newValue in
                            if newValue {
                                vault.enableBiometric()
                            } else {
                                vault.disableBiometric()
                            }
                        }
                    ))
                }
            }
            .padding(.vertical, 10)

            if !BiometricService.shared.isBiometricAvailable {
                Text("Touch ID is not available on this device")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(theme.textFaint)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    // MARK: - Breach Check

    private var breachCheckSection: some View {
        VStack(spacing: 4) {
            HStack {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.shield.fill")
                        .font(.system(size: 14))
                        .foregroundColor(theme.accentRed)
                    Text("Breach Detection")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                }
                Spacer()
                FlapsyToggle(isOn: Binding(
                    get: { settings.breachCheckEnabled },
                    set: { newValue in
                        settings.breachCheckEnabled = newValue
                        if newValue {
                            vault.runBreachCheck()
                        }
                    }
                ))
            }
            .padding(.vertical, 4)
            Text("Checks passwords against Have I Been Pwned on unlock. Only 5-char SHA-1 prefixes are sent \u{2014} full passwords never leave your device.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(theme.textFaint)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Secret Key

    private var secretKeySection: some View {
        VStack(alignment: .leading, spacing: 10) {
            FormLabel("SECRET KEY")

            VStack(alignment: .leading, spacing: 8) {
                Text("Your Secret Key adds an extra layer of encryption. Store it safely — you'll need it if you move to a new device.")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)

                if let formatted = vault.formattedSecretKey {
                    HStack(spacing: 8) {
                        Text(formatted)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundColor(theme.text)
                            .textSelection(.enabled)
                            .lineLimit(nil)

                        Spacer()

                        Button(action: { vault.copySecretKey() }) {
                            if vault.copiedField == "secretKey" {
                                Image(systemName: "checkmark")
                                    .font(.system(size: 12))
                                    .foregroundColor(theme.accentGreen)
                            } else {
                                Image(systemName: "doc.on.doc")
                                    .font(.system(size: 12))
                                    .foregroundColor(theme.accentBlueLt)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(10)
                    .background(theme.fieldBg)
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(theme.inputBorder, lineWidth: 1)
                    )
                } else if SecureEnclaveService.shared.hasWrappedKey {
                    HStack(spacing: 8) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 14))
                            .foregroundColor(theme.accentGreen)
                        Text("Protected by Secure Enclave")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(theme.accentGreen)
                    }
                    .padding(10)
                    .background(theme.accentGreen.opacity(0.08))
                    .cornerRadius(8)
                } else {
                    Text("No Secret Key found (v1 vault)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(theme.textFaint)
                }
            }
        }
    }

    // MARK: - Change Password

    private var changePasswordSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            FormLabel("CHANGE PASSWORD")

            // Current password
            ZStack(alignment: .leading) {
                if vault.changeOldPassword.isEmpty {
                    Text("Current password")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.textMuted)
                        .padding(10)
                }
                SecureField("", text: $vault.changeOldPassword)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(theme.text)
                    .padding(10)
            }
            .background(theme.inputBg)
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(theme.inputBorder, lineWidth: 1)
            )

            // New password
            VStack(alignment: .leading, spacing: 5) {
                ZStack(alignment: .leading) {
                    if vault.changeNewPassword.isEmpty {
                        Text("New password")
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundColor(theme.textMuted)
                            .padding(10)
                    }
                    SecureField("", text: $vault.changeNewPassword)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                        .padding(10)
                }
                .background(theme.inputBg)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(theme.inputBorder, lineWidth: 1)
                )

                // Strength bar
                if !vault.changeNewPassword.isEmpty {
                    let strength = vault.changeNewPasswordStrength
                    HStack(spacing: 8) {
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                RoundedRectangle(cornerRadius: 2)
                                    .fill(theme.fieldBg)
                                RoundedRectangle(cornerRadius: 2)
                                    .fill(PasswordStrength.color(for: strength))
                                    .frame(width: geo.size.width * CGFloat(strength) / 100)
                                    .animation(.easeInOut(duration: 0.3), value: strength)
                            }
                        }
                        .frame(height: 4)

                        Text("\(PasswordStrength.label(for: strength)) \(strength)%")
                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                            .foregroundColor(PasswordStrength.color(for: strength))
                            .fixedSize()
                    }
                }
            }

            // Confirm new password
            VStack(alignment: .leading, spacing: 5) {
                ZStack(alignment: .leading) {
                    if vault.changeConfirmPassword.isEmpty {
                        Text("Confirm new password")
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundColor(theme.textMuted)
                            .padding(10)
                    }
                    SecureField("", text: $vault.changeConfirmPassword)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                        .padding(10)
                }
                .background(theme.inputBg)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(
                            !vault.changeConfirmPassword.isEmpty && vault.changeConfirmPassword != vault.changeNewPassword
                                ? theme.accentRed : theme.inputBorder,
                            lineWidth: 1
                        )
                )

                if !vault.changeConfirmPassword.isEmpty {
                    if vault.changeConfirmPassword == vault.changeNewPassword {
                        Text("\u{2713} Passwords match")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(theme.accentGreen)
                    } else {
                        Text("\u{2715} Passwords do not match")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(theme.accentRed)
                    }
                }
            }

            // Error
            if !vault.changePasswordError.isEmpty {
                Text(vault.changePasswordError)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.accentRed)
            }

            // Success
            if vault.changePasswordSuccess {
                Text("\u{2713} Password updated")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.accentGreen)
            }

            // Submit button
            Button(action: { vault.changePassword() }) {
                HStack(spacing: 6) {
                    if vault.isChangingPassword {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                        Text("Updating...")
                            .font(.system(size: 13, weight: .semibold, design: .monospaced))
                            .foregroundColor(.white)
                    } else {
                        Image(systemName: "key.fill")
                            .font(.system(size: 12))
                            .foregroundColor(.white)
                        Text("Update Password")
                            .font(.system(size: 13, weight: .semibold, design: .monospaced))
                            .foregroundColor(.white)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(
                    LinearGradient(
                        colors: [Color(hex: "3b82f6"), Color(hex: "2563eb")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .cornerRadius(10)
                .opacity(vault.isChangingPassword ? 0.7 : 1)
            }
            .buttonStyle(.plain)
            .disabled(vault.isChangingPassword)
        }
    }

    // MARK: - Clipboard

    private var clipboardSection: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Clear Clipboard")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(theme.text)
                Spacer()
                FlapsyToggle(isOn: $settings.clipboardClearEnabled)
            }
            .padding(.vertical, 10)

            if settings.clipboardClearEnabled {
                VStack(spacing: 6) {
                    HStack {
                        Text("After")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(theme.textFaint)
                        Spacer()
                        Text("\(Int(settings.clipboardClearSeconds))s")
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                            .foregroundColor(theme.accentBlueLt)
                    }
                    Slider(value: $settings.clipboardClearSeconds, in: 5...120, step: 5)
                        .tint(theme.accentBlue)
                    HStack {
                        Text("5s")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundColor(theme.textGhost)
                        Spacer()
                        Text("120s")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundColor(theme.textGhost)
                    }
                }
                .padding(.leading, 4)
            }
        }
    }

    // MARK: - Open URL + Copy Password

    private var openURLCopySection: some View {
        VStack(spacing: 4) {
            HStack {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.up.forward.app")
                        .font(.system(size: 14))
                        .foregroundColor(theme.accentBlueLt)
                    Text("Open URL + Copy Password")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                }
                Spacer()
                FlapsyToggle(isOn: $settings.openURLCopyPassword)
            }
            .padding(.vertical, 4)
            Text("Shows a launch button that copies the password and opens the URL in your browser.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(theme.textFaint)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Default Favorites Filter

    private var favoritesDefaultSection: some View {
        HStack {
            HStack(spacing: 8) {
                Text("\u{2605}")
                    .font(.system(size: 16))
                    .foregroundColor(Color(hex: "fbbf24"))
                Text("Default Favorites Filter")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(theme.text)
            }
            Spacer()
            FlapsyToggle(isOn: $settings.defaultFavoritesFilter)
        }
        .padding(.vertical, 4)
    }

    // MARK: - Always Expand Notes

    private var expandNotesSection: some View {
        VStack(spacing: 4) {
            HStack {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.up.left.and.arrow.down.right")
                        .font(.system(size: 14))
                        .foregroundColor(theme.accentBlueLt)
                    Text("Always Expand Notes")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                }
                Spacer()
                FlapsyToggle(isOn: $settings.alwaysExpandNotes)
            }
            .padding(.vertical, 4)
            Text("Notes always open in full-height expanded view.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(theme.textFaint)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Delete Confirmation

    private var deleteConfirmSection: some View {
        HStack {
            HStack(spacing: 8) {
                Image(systemName: "trash")
                    .font(.system(size: 14))
                    .foregroundColor(theme.accentRed)
                Text("Confirm Before Delete")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(theme.text)
            }
            Spacer()
            FlapsyToggle(isOn: $settings.confirmBeforeDelete)
        }
        .padding(.vertical, 4)
    }

    // MARK: - Update Check

    private var updateCheckSection: some View {
        VStack(spacing: 4) {
            HStack {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.down.circle")
                        .font(.system(size: 14))
                        .foregroundColor(theme.accentBlueLt)
                    Text("Check for Updates")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.text)
                }
                Spacer()
                FlapsyToggle(isOn: $settings.checkForUpdates)
            }
            .padding(.vertical, 4)
            Text("Checks GitHub for new releases on launch. No data is sent.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(theme.textFaint)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Backup Reminder

    private var backupReminder: some View {
        Group {
            if settings.lastBackupDate == nil || Date().timeIntervalSince(settings.lastBackupDate!) > 30 * 24 * 60 * 60 {
                HStack(spacing: 10) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 14))
                        .foregroundColor(theme.accentYellow)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(settings.lastBackupDate == nil ? "No backup yet" : "Backup overdue")
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                            .foregroundColor(theme.accentYellow)
                        Text(backupReminderText)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(theme.textFaint)
                    }
                    Spacer()
                    Button(action: { vault.startExportBackup() }) {
                        Text("Backup")
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundColor(theme.accentBlueLt)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(theme.accentBlue.opacity(0.1))
                            .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                }
                .padding(12)
                .background(theme.accentYellow.opacity(0.06))
                .cornerRadius(10)
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(theme.accentYellow.opacity(0.2), lineWidth: 1)
                )
            }
        }
    }

    private var backupReminderText: String {
        guard let date = settings.lastBackupDate else {
            return "Export an encrypted backup to protect your data."
        }
        let days = Int(Date().timeIntervalSince(date) / (24 * 60 * 60))
        return "Last backup was \(days) day\(days == 1 ? "" : "s") ago."
    }

    // MARK: - Import / Export

    private var dataSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            FormLabel("DATA")
            VStack(spacing: 6) {
                Button(action: { vault.startImport() }) {
                    HStack(spacing: 10) {
                        Text("\u{1F4E5}")
                            .font(.system(size: 16))
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Import")
                                .font(.system(size: 13, weight: .medium, design: .monospaced))
                                .foregroundColor(theme.text)
                            Text("1Password, CSV, JSON, Bitwarden")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(theme.textFaint)
                        }
                        Spacer()
                        if settings.showImportSuccess {
                            Text("\u{2713} Imported")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(theme.accentGreen)
                        } else {
                            Text("\u{203A}")
                                .font(.system(size: 14))
                                .foregroundColor(theme.textGhost)
                        }
                    }
                    .padding(12)
                    .background(theme.fieldBg)
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(theme.inputBorder, lineWidth: 1)
                    )
                }
                .buttonStyle(.plain)
                .disabled(vault.isImporting)

                Button(action: { vault.startExportBackup() }) {
                    HStack(spacing: 10) {
                        Text("\u{1F4E4}")
                            .font(.system(size: 16))
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Export")
                                .font(.system(size: 13, weight: .medium, design: .monospaced))
                                .foregroundColor(theme.text)
                            Text("Encrypted backup or CSV")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(theme.textFaint)
                        }
                        Spacer()
                        if settings.showExportSuccess {
                            Text("\u{2713} Exported")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(theme.accentGreen)
                        } else {
                            Text("\u{203A}")
                                .font(.system(size: 14))
                                .foregroundColor(theme.textGhost)
                        }
                    }
                    .padding(12)
                    .background(theme.fieldBg)
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(theme.inputBorder, lineWidth: 1)
                    )
                }
                .buttonStyle(.plain)
            }
        }
    }

    // MARK: - Security Info

    private var securityInfo: some View {
        VStack(alignment: .leading, spacing: 10) {
            FormLabel("SECURITY")
            VStack(spacing: 5) {
                securityRow("Encryption", value: "AES-256-GCM")
                securityRow("KDF", value: Argon2Service.shared.parameterDescription)
                securityRow("Secret Key", value: SecureEnclaveService.shared.isAvailable ? "128-bit + HKDF + SE" : "128-bit + HKDF")
                securityRow("Key memory", value: "mlock + zero-wipe")
                securityRow("Anti-debug", value: "ptrace + sysctl")
                securityRow("File perms", value: "0600 owner-only")
                securityRow("Salt integrity", value: "SHA-256 checksum")
                securityRow("Brute-force", value: "Persistent lockout")
                securityRow("Clipboard", value: "Concealed + auto-clear")
                securityRow("Min password", value: "12 characters")
                securityRow("Storage", value: "Local only")
                securityRow("Vault HMAC", value: "HMAC-SHA256")
                securityRow("Edit re-auth", value: "Password / Touch ID")
                securityRow("Password history", value: "Last 20 changes")
                securityRow("Breach check", value: settings.breachCheckEnabled ? "HIBP k-Anonymity" : "Disabled")
                securityRow("Network", value: (settings.checkForUpdates || settings.breachCheckEnabled) ? "Update check + HIBP prefixes" : settings.checkForUpdates ? "Update check only" : "None")
                securityRow("Biometrics", value: "Touch ID")
            }
        }
        .padding(14)
        .background(theme.cardBg)
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(theme.cardBorder, lineWidth: 1)
        )
    }

    private func securityRow(_ label: String, value: String) -> some View {
        HStack {
            Text("\u{25C8} \(label)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(theme.textFaint)
            Spacer()
            Text(value)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundColor(theme.textSecondary)
        }
    }

    // MARK: - Vault Location

    private var vaultLocation: some View {
        VStack(alignment: .leading, spacing: 4) {
            FormLabel("VAULT LOCATION")
            Text(StorageService.shared.vaultFilePath)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(theme.textFaint)
                .lineLimit(nil)
        }
        .padding(12)
        .background(theme.cardBg)
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(theme.cardBorder, lineWidth: 1)
        )
    }

    // MARK: - Danger Zone

    private var dangerZoneSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            FormLabel("DANGER ZONE")

            VStack(alignment: .leading, spacing: 12) {
                Text("Permanently delete your vault and all stored passwords. This cannot be undone.")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)

                if vault.showResetConfirmation {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Type DELETE to confirm:")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .foregroundColor(theme.accentRed)

                        ZStack(alignment: .leading) {
                            if vault.resetConfirmText.isEmpty {
                                Text("DELETE")
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundColor(theme.textGhost)
                                    .padding(10)
                            }
                            TextField("", text: $vault.resetConfirmText)
                                .textFieldStyle(.plain)
                                .font(.system(size: 13, design: .monospaced))
                                .foregroundColor(theme.accentRed)
                                .padding(10)
                        }
                        .background(theme.inputBg)
                        .cornerRadius(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(theme.accentRed.opacity(0.5), lineWidth: 1)
                        )

                        HStack(spacing: 8) {
                            Button(action: { vault.cancelReset() }) {
                                Text("Cancel")
                                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                                    .foregroundColor(theme.textSecondary)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                                    .background(theme.fieldBg)
                                    .cornerRadius(8)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 8)
                                            .stroke(theme.inputBorder, lineWidth: 1)
                                    )
                            }
                            .buttonStyle(.plain)

                            Button(action: { vault.resetVault() }) {
                                Text("Delete Everything")
                                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                                    .background(
                                        vault.resetConfirmText == "DELETE"
                                            ? Color(hex: "dc2626")
                                            : Color(hex: "dc2626").opacity(0.3)
                                    )
                                    .cornerRadius(8)
                            }
                            .buttonStyle(.plain)
                            .disabled(vault.resetConfirmText != "DELETE")
                        }
                    }
                } else {
                    Button(action: { vault.showResetConfirmation = true }) {
                        HStack(spacing: 8) {
                            Image(systemName: "trash.fill")
                                .font(.system(size: 12))
                            Text("Delete All Data")
                                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                        }
                        .foregroundColor(theme.accentRed)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(theme.accentRed.opacity(0.1))
                        .cornerRadius(10)
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(theme.accentRed.opacity(0.3), lineWidth: 1)
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(14)
        .background(theme.cardBg)
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(theme.accentRed.opacity(0.3), lineWidth: 1)
        )
    }
}
