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

    /// Monospace security chip with a glowing accent dot (AES-256 / Argon2id).
    private func securityChip(_ text: String) -> some View {
        HStack(spacing: 7) {
            Circle()
                .fill(theme.accentBlue)
                .frame(width: 6, height: 6)
                .shadow(color: theme.accentBlue.opacity(0.7), radius: 4)
            Text(text)
                .font(.mono(11))
                .foregroundColor(theme.textMuted)
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 9)
                .fill(Color.white.opacity(0.02))
                .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(theme.cardBorder, lineWidth: 1))
        )
    }

    /// Branded purple gradient used by the lock badge + submit button.
    private var accentGradient: LinearGradient {
        LinearGradient(
            colors: [Color(hex: "9a8dff"), Color(hex: "5b49d6")],
            startPoint: .topLeading, endPoint: .bottomTrailing
        )
    }

    var body: some View {
        ZStack {
            // Base background + ambient aurora glow behind the lock badge.
            theme.bg.ignoresSafeArea()
            Ellipse()
                .fill(theme.accentBlue.opacity(0.30))
                .frame(width: 360, height: 300)
                .blur(radius: 80)
                .offset(y: -190)
                .allowsHitTesting(false)

            VStack(spacing: 0) {
                VStack(spacing: 18) {
                    Spacer().frame(height: 26)

                    // Lock badge in a glowing well
                    ZStack {
                        RoundedRectangle(cornerRadius: 22)
                            .fill(accentGradient)
                            .frame(width: 76, height: 76)
                            .shadow(color: Color(hex: "5b49d6").opacity(0.65), radius: 22, y: 8)
                            .shadow(color: theme.accentBlue.opacity(0.55), radius: 48)
                            .overlay(
                                RoundedRectangle(cornerRadius: 22)
                                    .strokeBorder(Color.white.opacity(0.14), lineWidth: 1)
                            )
                        Image(systemName: "lock.fill")
                            .font(.system(size: 30, weight: .medium))
                            .foregroundColor(.white)
                    }

                    // Title
                    VStack(spacing: 6) {
                        Text("Flapsy")
                            .font(.ui(29, weight: .bold))
                            .foregroundColor(theme.text)
                        Text("Enter master password to unlock")
                            .font(.ui(14))
                            .foregroundColor(theme.textSecondary)
                    }

                    // Touch ID (above the password field)
                    if biometricAvailableAndEnabled && !vault.needsSecretKeyRecovery {
                        Button(action: { vault.attemptBiometricUnlock() }) {
                            HStack(spacing: 12) {
                                Image(systemName: "touchid")
                                    .font(.system(size: 22))
                                Text("Unlock with Touch ID")
                                    .font(.ui(15, weight: .semibold))
                            }
                            .foregroundColor(theme.accentBlueLt)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 15)
                            .background(
                                RoundedRectangle(cornerRadius: 16)
                                    .fill(
                                        LinearGradient(
                                            colors: [theme.accentBlue.opacity(0.16), theme.accentBlue.opacity(0.06)],
                                            startPoint: .top, endPoint: .bottom
                                        )
                                    )
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16)
                                            .strokeBorder(theme.accentBlue.opacity(0.32), lineWidth: 1)
                                    )
                            )
                        }
                        .buttonStyle(.hand)
                        .disabled(vault.showBiometricPrompt)
                        .padding(.top, 6)

                        // Divider
                        HStack(spacing: 14) {
                            Rectangle()
                                .fill(LinearGradient(colors: [.clear, theme.cardBorder, .clear], startPoint: .leading, endPoint: .trailing))
                                .frame(height: 1)
                            Text("or enter master password")
                                .font(.ui(12.5, weight: .medium))
                                .foregroundColor(theme.textFaint)
                                .fixedSize()
                            Rectangle()
                                .fill(LinearGradient(colors: [.clear, theme.cardBorder, .clear], startPoint: .leading, endPoint: .trailing))
                                .frame(height: 1)
                        }
                        .padding(.top, 2)
                    }

                    // Password input with inline arrow-submit button
                    HStack(spacing: 7) {
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
                                        .font(.system(size: 17, weight: .semibold))
                                }
                            }
                            .foregroundColor(.white)
                            .frame(width: 44, height: 44)
                            .background(RoundedRectangle(cornerRadius: 11).fill(accentGradient))
                            .shadow(color: Color(hex: "5b49d6").opacity(0.55), radius: 10, y: 3)
                        }
                        .buttonStyle(.hand)
                        .keyboardShortcut(.defaultAction)
                        .disabled(vault.isLoading || vault.isLockedOut || vault.masterPasswordInput.isEmpty)
                    }
                    .padding(.leading, 18)
                    .padding(.trailing, 6)
                    .padding(.vertical, 6)
                    .background(theme.inputBg)
                    .cornerRadius(16)
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(vault.lockError ? theme.accentRed : theme.inputBorder, lineWidth: 1)
                    )
                    .modifier(ShakeModifier(shakes: vault.shakeError ? 3 : 0))

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
                    }

                    // Security chips
                    HStack(spacing: 10) {
                        securityChip("AES-256")
                        securityChip("Argon2id")
                    }
                    .padding(.top, 6)

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
                                    .font(.mono(11))
                            }
                            .foregroundColor(theme.accentBlueLt)
                        }
                        .buttonStyle(.hand)
                    } else {
                        Text("v\(updateCheck.currentVersion)")
                            .font(.mono(11))
                            .foregroundColor(theme.textFaint)
                    }
                }
                .padding(.horizontal, 32)

                Spacer(minLength: 20)

                // Footer pinned to bottom (full-width with a top hairline)
                HStack {
                    Button(action: {
                        vault.showStartFreshConfirmation = true
                    }) {
                        HStack(spacing: 7) {
                            Image(systemName: "arrow.counterclockwise")
                                .font(.system(size: 11, weight: .semibold))
                            Text("Start Fresh")
                                .font(.ui(13, weight: .medium))
                        }
                        .foregroundColor(theme.textFaint)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.hand)

                    Spacer()

                    Button(action: { NSApplication.shared.terminate(nil) }) {
                        HStack(spacing: 7) {
                            Image(systemName: "xmark")
                                .font(.system(size: 11, weight: .semibold))
                            Text("Quit Application")
                                .font(.ui(13, weight: .medium))
                        }
                        .foregroundColor(theme.textFaint)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.hand)
                }
                .padding(.horizontal, 22)
                .padding(.vertical, 14)
                .background(
                    theme.bg.opacity(0.4)
                        .overlay(theme.cardBorder.frame(height: 1), alignment: .top)
                )
            }
        }
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
