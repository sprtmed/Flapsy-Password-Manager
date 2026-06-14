import SwiftUI

/// First-launch screen: Create Master Password
struct SetupView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @FocusState private var focusedField: Field?

    enum Field {
        case password, confirm
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 20) {
                    Spacer().frame(height: 16)

                    // Shield icon
                    ZStack {
                        RoundedRectangle(cornerRadius: 20)
                            .fill(
                                LinearGradient(
                                    colors: [Color(hex: "3b82f6"), Color(hex: "1d4ed8")],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 64, height: 64)
                            .shadow(color: Color(hex: "3b82f6").opacity(0.3), radius: 16, y: 8)

                        Image(systemName: "shield.lefthalf.filled")
                            .font(.system(size: 28))
                            .foregroundColor(.white)
                    }

                    // Title
                    VStack(spacing: 6) {
                        Text("Welcome to Flapsy")
                            .font(.ui(18, weight: .bold))
                            .foregroundColor(theme.text)
                        Text("Create a master password to protect your vault")
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
                            .onSubmit { vault.createMasterPassword() }

                        // Match indicator
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

                    // Error
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

                    // Security badges
                    HStack(spacing: 16) {
                        Label("AES-256", systemImage: "diamond.fill")
                            .font(.ui(10))
                            .foregroundColor(theme.textGhost)
                        Label("Argon2id", systemImage: "diamond.fill")
                            .font(.ui(10))
                            .foregroundColor(theme.textGhost)
                        Label("Secret Key", systemImage: "diamond.fill")
                            .font(.ui(10))
                            .foregroundColor(theme.textGhost)
                    }

                    Text("Your password never leaves this device.\nAll data is encrypted locally with a Secret Key.")
                        .font(.ui(10))
                        .foregroundColor(theme.textGhost)
                        .multilineTextAlignment(.center)

                    Spacer()
                }
                .padding(.horizontal, 32)
            }
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
        vault.setupPasswordStrength >= PasswordStrength.minimumRequired &&
        vault.setupPassword == vault.setupConfirm
    }
}
