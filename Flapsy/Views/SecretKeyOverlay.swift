import SwiftUI

/// Full-screen overlay shown after vault creation or v1→v2 migration
/// to display the user's Secret Key ("Emergency Kit").
struct SecretKeyOverlay: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @State private var hasCopied = false

    var body: some View {
        ZStack {
            theme.dropBg.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 20) {
                    Spacer().frame(height: 24)

                    // Key icon
                    ZStack {
                        RoundedRectangle(cornerRadius: 20)
                            .fill(
                                LinearGradient(
                                    colors: [Color(hex: "f59e0b"), Color(hex: "d97706")],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 64, height: 64)
                            .shadow(color: Color(hex: "f59e0b").opacity(0.3), radius: 16, y: 8)

                        Image(systemName: "key.fill")
                            .font(.system(size: 28))
                            .foregroundColor(.white)
                    }

                    // Title
                    VStack(spacing: 6) {
                        Text("Your Secret Key")
                            .font(.system(size: 18, weight: .bold, design: .monospaced))
                            .foregroundColor(theme.text)
                        Text("Save this key somewhere safe. You'll need it\nto sign in on a new device.")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(theme.textMuted)
                            .multilineTextAlignment(.center)
                    }

                    // Secret Key display
                    VStack(spacing: 10) {
                        Text(vault.displayedSecretKey)
                            .font(.system(size: 13, weight: .semibold, design: .monospaced))
                            .foregroundColor(theme.text)
                            .textSelection(.enabled)
                            .multilineTextAlignment(.center)
                            .padding(16)
                            .frame(maxWidth: .infinity)
                            .background(theme.fieldBg)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Color(hex: "f59e0b").opacity(0.3), lineWidth: 1)
                            )

                        // Copy button
                        Button(action: {
                            vault.copySecretKey()
                            hasCopied = true
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: hasCopied ? "checkmark" : "doc.on.doc")
                                    .font(.system(size: 12))
                                Text(hasCopied ? "Copied!" : "Copy Secret Key")
                                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                            }
                            .foregroundColor(hasCopied ? theme.accentGreen : theme.accentBlueLt)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.fieldBg)
                            .cornerRadius(8)
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(theme.inputBorder, lineWidth: 1)
                            )
                        }
                        .buttonStyle(.hand)
                    }
                    .padding(.horizontal, 32)

                    // Warning
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 12))
                                .foregroundColor(Color(hex: "f59e0b"))
                            Text("Important")
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                                .foregroundColor(theme.text)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            warningBullet("This key cannot be recovered if lost")
                            warningBullet("Store it in a safe place (not this device)")
                            warningBullet("You need both your password AND this key")
                        }
                    }
                    .padding(14)
                    .background(Color(hex: "f59e0b").opacity(0.06))
                    .cornerRadius(10)
                    .overlay(
                        RoundedRectangle(cornerRadius: 10)
                            .stroke(Color(hex: "f59e0b").opacity(0.15), lineWidth: 1)
                    )
                    .padding(.horizontal, 32)

                    // Continue button
                    Button(action: { vault.dismissSecretKeyDisplay() }) {
                        Text("I've saved my Secret Key")
                            .font(.system(size: 13, weight: .semibold))
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
                    }
                    .buttonStyle(.hand)
                    .padding(.horizontal, 32)

                    Spacer().frame(height: 16)
                }
            }
        }
    }

    private func warningBullet(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("\u{2022}")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(theme.textMuted)
            Text(text)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
