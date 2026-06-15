import SwiftUI

struct LockScreenView: View {
    @EnvironmentObject var vault: VaultViewModel
    @EnvironmentObject var updateCheck: UpdateCheckService
    @Environment(\.theme) var theme

    @FocusState private var isPasswordFocused: Bool
    @State private var biometricAvailableAndEnabled: Bool = false

    private func refreshBiometricAvailability() {
        biometricAvailableAndEnabled =
            BiometricService.shared.isBiometricAvailable &&
            KeychainService.biometricEnabledFlag
    }

    var body: some View {
        VStack(spacing: 20) {
            Spacer().frame(height: 40)

            // Lock icon with blue gradient
            ZStack {
                RoundedRectangle(cornerRadius: 20)
                    .fill(
                        LinearGradient(
                            colors: [theme.accentBlue, Color(hex: "8a6bea")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: 64, height: 64)
                    .shadow(color: theme.accentBlue.opacity(0.3), radius: 16, y: 8)

                Image(systemName: "lock.fill")
                    .font(.system(size: 28))
                    .foregroundColor(.white)
            }

            // Title
            VStack(spacing: 6) {
                Text("Flapsy")
                    .font(.ui(18, weight: .bold))
                    .foregroundColor(theme.text)
                Text("Enter master password to unlock")
                    .font(.ui(12))
                    .foregroundColor(theme.textSecondary)
            }

            // Touch ID (above the password field)
            if biometricAvailableAndEnabled && !vault.needsSecretKeyRecovery {
                Button(action: { vault.attemptBiometricUnlock() }) {
                    HStack(spacing: 8) {
                        Image(systemName: "touchid")
                            .font(.system(size: 20))
                        Text("Unlock with Touch ID")
                            .font(.ui(13, weight: .medium))
                    }
                    .foregroundColor(theme.accentBlueLt)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.hand)
                .disabled(vault.showBiometricPrompt)

                // Divider
                HStack(spacing: 10) {
                    Rectangle().fill(theme.cardBorder).frame(height: 1)
                    Text("or enter master password")
                        .font(.ui(11))
                        .foregroundColor(theme.textMuted)
                        .fixedSize()
                    Rectangle().fill(theme.cardBorder).frame(height: 1)
                }
                .padding(.horizontal, 32)
            }

            // Password input with inline arrow-submit button
            HStack(spacing: 6) {
                ZStack(alignment: .leading) {
                    if vault.masterPasswordInput.isEmpty {
                        Text("Master password")
                            .font(.ui(15))
                            .foregroundColor(theme.textFaint)
                    }
                    SecureField("", text: $vault.masterPasswordInput)
                        .textFieldStyle(.plain)
                        .font(.ui(15))
                        .foregroundColor(theme.text)
                        .focused($isPasswordFocused)
                }
                Button(action: {
                    if vault.needsSecretKeyRecovery {
                        vault.unlockWithRecoveredSecretKey()
                    } else {
                        vault.unlock()
                    }
                }) {
                    Group {
                        if vault.isLoading {
                            ProgressView()
                                .scaleEffect(0.6)
                                .progressViewStyle(.circular)
                                .tint(.white)
                        } else {
                            Image(systemName: "arrow.right")
                                .font(.system(size: 15, weight: .semibold))
                        }
                    }
                    .foregroundColor(.white)
                    .frame(width: 38, height: 38)
                    .background(theme.accentBlue)
                    .cornerRadius(9)
                }
                .buttonStyle(.hand)
                .keyboardShortcut(.defaultAction)
                .disabled(vault.isLoading || vault.isLockedOut || vault.masterPasswordInput.isEmpty)
            }
            .padding(.leading, 14)
            .padding(.trailing, 5)
            .padding(.vertical, 5)
            .background(theme.inputBg)
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(vault.lockError ? theme.accentRed : theme.inputBorder, lineWidth: 1)
            )
            .modifier(ShakeModifier(shakes: vault.shakeError ? 3 : 0))
            .padding(.horizontal, 32)

            // Error message
            if vault.lockError {
                Text("\u{2715} \(vault.lockErrorMessage)")
                    .font(.ui(11))
                    .foregroundColor(theme.accentRed)
            }

            // Lockout countdown
            if vault.isLockedOut {
                Text("Wait \(vault.lockoutRemainingSeconds)s before trying again")
                    .font(.ui(11, weight: .medium))
                    .foregroundColor(theme.accentRed.opacity(0.8))
            }

            // Biometric failed message
            if vault.biometricFailed {
                Text("Touch ID failed \u{2014} enter your password")
                    .font(.ui(11))
                    .foregroundColor(theme.textMuted)
            }

            // Secret Key recovery input (shown when Keychain lost for v2 vault)
            if vault.needsSecretKeyRecovery {
                VStack(alignment: .leading, spacing: 6) {
                    Text("SECRET KEY")
                        .font(.ui(10, weight: .semibold))
                        .foregroundColor(theme.textFaint)

                    TextField("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", text: $vault.secretKeyRecoveryInput)
                        .textFieldStyle(.plain)
                        .font(.ui(12))
                        .padding(10)
                        .background(theme.inputBg)
                        .cornerRadius(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(
                                    vault.secretKeyRecoveryError.isEmpty ? theme.inputBorder : theme.accentRed,
                                    lineWidth: 1
                                )
                        )
                        .foregroundColor(theme.text)

                    if !vault.secretKeyRecoveryError.isEmpty {
                        Text(vault.secretKeyRecoveryError)
                            .font(.ui(10))
                            .foregroundColor(theme.accentRed)
                    }

                    Text("Enter the Secret Key from your Emergency Kit")
                        .font(.ui(10))
                        .foregroundColor(theme.textMuted)
                }
                .padding(.horizontal, 32)
            }

            // Security badges
            HStack(spacing: 16) {
                Label("AES-256", systemImage: "diamond.fill")
                    .font(.ui(10))
                    .foregroundColor(theme.textGhost)
                Label("Argon2id", systemImage: "diamond.fill")
                    .font(.ui(10))
                    .foregroundColor(theme.textGhost)
            }

            // Version info
            if updateCheck.updateAvailable, let version = updateCheck.latestVersion {
                Button(action: {
                    if let url = URL(string: "https://github.com/sprtmed/Flapsy-Password-Manager/releases/latest") {
                        NSWorkspace.shared.open(url)
                    }
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.down.circle")
                            .font(.system(size: 9))
                        Text("v\(version) available")
                            .font(.ui(10))
                    }
                    .foregroundColor(theme.accentBlueLt)
                }
                .buttonStyle(.hand)
            } else {
                Text("v\(updateCheck.currentVersion)")
                    .font(.ui(10))
                    .foregroundColor(theme.textGhost)
            }

            Spacer()

            // Quit + Start Fresh
            HStack {
                Button(action: {
                    vault.showStartFreshConfirmation = true
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.counterclockwise")
                            .font(.system(size: 8, weight: .semibold))
                        Text("Start Fresh")
                            .font(.ui(9))
                    }
                    .foregroundColor(theme.textGhost)
                }
                .buttonStyle(.hand)

                Spacer()

                Button(action: { NSApplication.shared.terminate(nil) }) {
                    HStack(spacing: 4) {
                        Image(systemName: "xmark")
                            .font(.system(size: 8, weight: .semibold))
                        Text("Quit Application")
                            .font(.ui(9))
                    }
                    .foregroundColor(theme.textGhost)
                }
                .buttonStyle(.hand)
            }
            .padding(.bottom, 16)
        }
        .padding(.horizontal, 32)
        .overlay {
            if vault.showStartFreshConfirmation {
                ZStack {
                    Color.black.opacity(0.85)

                    VStack(spacing: 16) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 28))
                            .foregroundColor(theme.accentRed)

                        Text("Delete Vault & Start Fresh")
                            .font(.ui(14, weight: .bold))
                            .foregroundColor(theme.text)

                        Text("This will permanently delete your vault and all saved logins. A backup copy will be saved as vault.enc.bak.")
                            .font(.ui(11))
                            .foregroundColor(theme.textSecondary)
                            .multilineTextAlignment(.center)

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Type DESTROY to confirm:")
                                .font(.ui(10, weight: .semibold))
                                .foregroundColor(theme.textFaint)

                            TextField("", text: $vault.startFreshConfirmText)
                                .textFieldStyle(.plain)
                                .font(.ui(14, weight: .bold))
                                .multilineTextAlignment(.center)
                                .padding(8)
                                .background(theme.inputBg)
                                .cornerRadius(8)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(theme.inputBorder, lineWidth: 1)
                                )
                                .foregroundColor(theme.accentRed)
                        }

                        HStack(spacing: 12) {
                            Button(action: { vault.cancelStartFresh() }) {
                                Text("Cancel")
                                    .font(.ui(12, weight: .medium))
                                    .foregroundColor(theme.textSecondary)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                                    .background(theme.inputBg)
                                    .cornerRadius(8)
                            }
                            .buttonStyle(.hand)

                            Button(action: { vault.startFresh() }) {
                                Text("Delete & Start Fresh")
                                    .font(.ui(12, weight: .bold))
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                                    .background(
                                        vault.startFreshConfirmText == "DESTROY"
                                            ? Color(hex: "ef4444")
                                            : Color(hex: "ef4444").opacity(0.3)
                                    )
                                    .cornerRadius(8)
                            }
                            .buttonStyle(.hand)
                            .disabled(vault.startFreshConfirmText != "DESTROY")
                        }
                    }
                    .padding(24)
                    .background(theme.cardBg)
                    .cornerRadius(16)
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(theme.cardBorder, lineWidth: 1)
                    )
                    .shadow(color: .black.opacity(0.3), radius: 20, y: 10)
                    .padding(.horizontal, 24)
                }
            }
        }
        .onAppear {
            refreshBiometricAvailability()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                isPasswordFocused = true
            }
            // Re-check availability — LAContext can briefly return false right after
            // wake/popover-open while the biometric subsystem is still coming online.
            for delay in [0.15, 0.4, 0.8, 1.5] {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                    refreshBiometricAvailability()
                }
            }
            // Auto-trigger Touch ID if enabled
            if BiometricService.shared.isBiometricAvailable && KeychainService.biometricEnabledFlag {
                vault.attemptBiometricUnlock()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            refreshBiometricAvailability()
        }
    }

}

// MARK: - Shake Animation Modifier

struct ShakeModifier: GeometryEffect {
    var shakes: Int
    var animatableData: CGFloat {
        get { CGFloat(shakes) }
        set { shakes = Int(newValue) }
    }

    func effectValue(size: CGSize) -> ProjectionTransform {
        let translation = sin(animatableData * .pi * 2) * 8
        return ProjectionTransform(CGAffineTransform(translationX: translation, y: 0))
    }
}
