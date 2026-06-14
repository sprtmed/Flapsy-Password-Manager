import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var vault: VaultViewModel
    @EnvironmentObject var settings: SettingsViewModel
    @Environment(\.theme) var theme

    @State private var step: Int = 0
    @State private var enableTouchID: Bool = true
    @FocusState private var focusedField: SetupField?

    enum SetupField {
        case password, confirm
    }

    private var totalSteps: Int {
        BiometricService.shared.isBiometricAvailable ? 5 : 4
    }

    var body: some View {
        VStack(spacing: 0) {
            // Progress dots
            progressDots
                .padding(.top, 16)

            // Step content
            ScrollView {
                Group {
                    switch step {
                    case 0: welcomeStep
                    case 1: createPasswordStep
                    case 2:
                        if BiometricService.shared.isBiometricAvailable {
                            touchIDStep
                        } else {
                            importStep
                        }
                    case 3:
                        if BiometricService.shared.isBiometricAvailable {
                            importStep
                        } else {
                            completionStep
                        }
                    case 4: completionStep
                    default: EmptyView()
                    }
                }
                .padding(.horizontal, 32)
            }
        }
        .onChange(of: vault.onboardingPasswordCreated) { created in
            if created {
                withAnimation(.easeInOut(duration: 0.3)) {
                    step = 2
                }
            }
        }
    }

    // MARK: - Progress Dots

    private var progressDots: some View {
        HStack(spacing: 8) {
            ForEach(0..<totalSteps, id: \.self) { i in
                Circle()
                    .fill(i <= step ? theme.accentBlue : theme.textGhost)
                    .frame(width: 8, height: 8)
                    .animation(.easeInOut(duration: 0.2), value: step)
            }
        }
    }

    // MARK: - Step 0: Welcome

    private var welcomeStep: some View {
        VStack(spacing: 24) {
            Spacer().frame(height: 40)

            // Shield icon
            ZStack {
                RoundedRectangle(cornerRadius: 24)
                    .fill(
                        LinearGradient(
                            colors: [Color(hex: "3b82f6"), Color(hex: "1d4ed8")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: 80, height: 80)
                    .shadow(color: Color(hex: "3b82f6").opacity(0.3), radius: 20, y: 10)

                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 36))
                    .foregroundColor(.white)
            }

            VStack(spacing: 8) {
                Text("Welcome to Flapsy")
                    .font(.ui(20, weight: .bold))
                    .foregroundColor(theme.text)
                Text("Your passwords, encrypted locally.")
                    .font(.ui(13))
                    .foregroundColor(theme.textSecondary)
            }

            VStack(spacing: 8) {
                featureBadge(icon: "lock.shield.fill", text: "AES-256-GCM encryption")
                featureBadge(icon: "desktopcomputer", text: "Never leaves your device")
                featureBadge(icon: "network.slash", text: "No network access")
            }
            .padding(.top, 8)

            Spacer().frame(height: 20)

            Button(action: {
                withAnimation(.easeInOut(duration: 0.3)) {
                    step = 1
                }
            }) {
                Text("Get Started")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(
                        LinearGradient(
                            colors: [Color(hex: "3b82f6"), Color(hex: "2563eb")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .cornerRadius(10)
            }
            .buttonStyle(.hand)

            Spacer()
        }
    }

    private func featureBadge(icon: String, text: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 12))
                .foregroundColor(theme.accentBlueLt)
                .frame(width: 20)
            Text(text)
                .font(.ui(12))
                .foregroundColor(theme.textSecondary)
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(theme.fieldBg)
        .cornerRadius(8)
    }

    // MARK: - Step 1: Create Password

    private var createPasswordStep: some View {
        VStack(spacing: 20) {
            Spacer().frame(height: 20)

            VStack(spacing: 6) {
                Text("Create Master Password")
                    .font(.ui(16, weight: .bold))
                    .foregroundColor(theme.text)
                Text("This is the only password you\u{2019}ll need to remember")
                    .font(.ui(12))
                    .foregroundColor(theme.textMuted)
                    .multilineTextAlignment(.center)
            }

            // Password field
            VStack(alignment: .leading, spacing: 5) {
                FormLabel("MASTER PASSWORD")
                ZStack(alignment: .leading) {
                    if vault.setupPassword.isEmpty {
                        Text("At least 12 characters")
                            .font(.ui(13))
                            .foregroundColor(theme.textMuted)
                            .padding(10)
                    }
                    SecureField("", text: $vault.setupPassword)
                        .textFieldStyle(.plain)
                        .font(.ui(13))
                        .foregroundColor(theme.text)
                        .padding(10)
                }
                .background(theme.inputBg)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(theme.inputBorder, lineWidth: 1)
                )
                .focused($focusedField, equals: .password)
                .onSubmit { focusedField = .confirm }

                // Strength bar
                if !vault.setupPassword.isEmpty {
                    let strength = vault.setupPasswordStrength
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
                            .font(.ui(10, weight: .semibold))
                            .foregroundColor(PasswordStrength.color(for: strength))
                            .fixedSize()
                    }
                }
            }

            // Confirm field
            VStack(alignment: .leading, spacing: 5) {
                FormLabel("CONFIRM PASSWORD")
                ZStack(alignment: .leading) {
                    if vault.setupConfirm.isEmpty {
                        Text("Re-enter password")
                            .font(.ui(13))
                            .foregroundColor(theme.textMuted)
                            .padding(10)
                    }
                    SecureField("", text: $vault.setupConfirm)
                        .textFieldStyle(.plain)
                        .font(.ui(13))
                        .foregroundColor(theme.text)
                        .padding(10)
                }
                .background(theme.inputBg)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(
                            !vault.setupConfirm.isEmpty && vault.setupConfirm != vault.setupPassword
                                ? theme.accentRed : theme.inputBorder,
                            lineWidth: 1
                        )
                )
                .focused($focusedField, equals: .confirm)
                    .onSubmit {
                        if canCreate { vault.createMasterPassword() }
                    }

                if !vault.setupConfirm.isEmpty {
                    if vault.setupConfirm == vault.setupPassword {
                        Text("\u{2713} Passwords match")
                            .font(.ui(10))
                            .foregroundColor(theme.accentGreen)
                    } else {
                        Text("\u{2715} Passwords do not match")
                            .font(.ui(10))
                            .foregroundColor(theme.accentRed)
                    }
                }
            }

            if !vault.setupError.isEmpty {
                Text(vault.setupError)
                    .font(.ui(11))
                    .foregroundColor(theme.accentRed)
                    .multilineTextAlignment(.center)
            }

            // Create button
            Button(action: { vault.createMasterPassword() }) {
                HStack(spacing: 8) {
                    if vault.isLoading {
                        ProgressView()
                            .scaleEffect(0.7)
                            .progressViewStyle(.circular)
                        Text("Deriving key\u{2026}")
                            .font(.system(size: 13, weight: .semibold))
                    } else {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 12))
                        Text("Create Encrypted Vault")
                            .font(.system(size: 13, weight: .semibold))
                    }
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 11)
                .background(
                    LinearGradient(
                        colors: [Color(hex: "3b82f6"), Color(hex: "2563eb")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .cornerRadius(10)
                .opacity(canCreate ? 1.0 : 0.4)
            }
            .buttonStyle(.hand)
            .disabled(!canCreate || vault.isLoading)

            Text("Your password never leaves this device.")
                .font(.ui(10))
                .foregroundColor(theme.textGhost)
                .multilineTextAlignment(.center)

            Spacer()
        }
        .onAppear {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                focusedField = .password
            }
        }
    }

    private var canCreate: Bool {
        !vault.setupPassword.isEmpty &&
        vault.setupPassword.count >= 12 &&
        vault.setupPassword == vault.setupConfirm
    }

    // MARK: - Step 2: Touch ID

    private var touchIDStep: some View {
        VStack(spacing: 24) {
            Spacer().frame(height: 40)

            Image(systemName: "touchid")
                .font(.system(size: 56))
                .foregroundColor(theme.accentBlueLt)

            VStack(spacing: 6) {
                Text("Enable Touch ID?")
                    .font(.ui(16, weight: .bold))
                    .foregroundColor(theme.text)
                Text("Unlock your vault faster with Touch ID.\nYour master password is never stored.")
                    .font(.ui(12))
                    .foregroundColor(theme.textSecondary)
                    .multilineTextAlignment(.center)
            }

            HStack {
                Text("Enable Touch ID")
                    .font(.ui(13))
                    .foregroundColor(theme.text)
                Spacer()
                FlapsyToggle(isOn: $enableTouchID)
            }
            .padding(14)
            .background(theme.fieldBg)
            .cornerRadius(10)
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(theme.inputBorder, lineWidth: 1)
            )

            Button(action: {
                if enableTouchID {
                    vault.enableBiometric()
                }
                withAnimation(.easeInOut(duration: 0.3)) {
                    step = 3
                }
            }) {
                Text("Continue")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(
                        LinearGradient(
                            colors: [Color(hex: "3b82f6"), Color(hex: "2563eb")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .cornerRadius(10)
            }
            .buttonStyle(.hand)

            Spacer()
        }
    }

    // MARK: - Step 3: Import

    private var importStep: some View {
        let completionStepIndex = BiometricService.shared.isBiometricAvailable ? 4 : 3

        return VStack(spacing: 24) {
            Spacer().frame(height: 40)

            Text("\u{1F4E5}")
                .font(.system(size: 48))

            VStack(spacing: 6) {
                Text("Import Existing Passwords?")
                    .font(.ui(16, weight: .bold))
                    .foregroundColor(theme.text)
                Text("Bring your passwords from another manager")
                    .font(.ui(12))
                    .foregroundColor(theme.textSecondary)
            }

            VStack(spacing: 6) {
                importFormatRow("1Password", detail: "CSV export")
                importFormatRow("Bitwarden", detail: "JSON or CSV")
                importFormatRow("Chrome", detail: "Passwords CSV")
                importFormatRow("Generic CSV", detail: "Auto-detect columns")
            }

            HStack(spacing: 10) {
                Button(action: {
                    withAnimation(.easeInOut(duration: 0.3)) {
                        step = completionStepIndex
                    }
                }) {
                    Text("Skip")
                        .font(.ui(13, weight: .medium))
                        .foregroundColor(theme.textSecondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .background(theme.fieldBg)
                        .cornerRadius(10)
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(theme.inputBorder, lineWidth: 1)
                        )
                }
                .buttonStyle(.hand)

                Button(action: {
                    vault.startImport()
                    // After import completes, advance to completion
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                        if !vault.showImportPreview {
                            withAnimation(.easeInOut(duration: 0.3)) {
                                step = completionStepIndex
                            }
                        }
                    }
                }) {
                    HStack(spacing: 6) {
                        Image(systemName: "square.and.arrow.down")
                            .font(.system(size: 12))
                        Text("Import Now")
                            .font(.system(size: 13, weight: .semibold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(
                        LinearGradient(
                            colors: [Color(hex: "3b82f6"), Color(hex: "2563eb")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .cornerRadius(10)
                }
                .buttonStyle(.hand)
            }

            Spacer()
        }
    }

    private func importFormatRow(_ name: String, detail: String) -> some View {
        HStack {
            Text(name)
                .font(.ui(12, weight: .medium))
                .foregroundColor(theme.text)
            Spacer()
            Text(detail)
                .font(.ui(11))
                .foregroundColor(theme.textFaint)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(theme.fieldBg)
        .cornerRadius(8)
    }

    // MARK: - Step 4: Completion

    private var completionStep: some View {
        VStack(spacing: 24) {
            Spacer().frame(height: 50)

            ZStack {
                Circle()
                    .fill(theme.accentGreen.opacity(0.12))
                    .frame(width: 80, height: 80)
                Image(systemName: "checkmark")
                    .font(.system(size: 36, weight: .bold))
                    .foregroundColor(theme.accentGreen)
            }

            VStack(spacing: 6) {
                Text("You\u{2019}re All Set!")
                    .font(.ui(18, weight: .bold))
                    .foregroundColor(theme.text)
                Text("Your vault is ready with AES-256 encryption")
                    .font(.ui(12))
                    .foregroundColor(theme.textSecondary)
            }

            Button(action: {
                vault.isOnboarding = false
                vault.onboardingPasswordCreated = false
                vault.currentScreen = .vault
                vault.currentPanel = .list
            }) {
                HStack(spacing: 8) {
                    Image(systemName: "lock.open.fill")
                        .font(.system(size: 12))
                    Text("Open Vault")
                        .font(.system(size: 14, weight: .semibold))
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(
                    LinearGradient(
                        colors: [Color(hex: "3b82f6"), Color(hex: "2563eb")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .cornerRadius(10)
            }
            .buttonStyle(.hand)

            Spacer()
        }
    }
}
