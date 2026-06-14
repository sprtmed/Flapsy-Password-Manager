import SwiftUI

struct ExportView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @State private var selectedFormat: ExportService.ExportFormat = .encryptedBackup

    var body: some View {
        VStack(spacing: 16) {
            // Header
            HStack {
                Text("\u{1F4E4} Export Vault")
                    .font(.system(size: 14, weight: .bold, design: .monospaced))
                    .foregroundColor(theme.text)
                Spacer()
                Button(action: { vault.cancelExport() }) {
                    Text("\u{2715}")
                        .font(.system(size: 14))
                        .foregroundColor(theme.textMuted)
                }
                .buttonStyle(.hand)
            }

            // Format picker
            VStack(alignment: .leading, spacing: 8) {
                FormLabel("FORMAT")
                ForEach(ExportService.ExportFormat.allCases, id: \.self) { format in
                    formatRow(format)
                }
            }

            // Format-specific content
            if selectedFormat == .encryptedBackup {
                encryptedBackupSection
            } else {
                csvSection
            }

            // Error message
            if !vault.exportError.isEmpty {
                Text("\u{2715} \(vault.exportError)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.accentRed)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(16)
    }

    // MARK: - Format Row

    private func formatRow(_ format: ExportService.ExportFormat) -> some View {
        let isSelected = selectedFormat == format
        return Button(action: {
            selectedFormat = format
            vault.exportError = ""
        }) {
            HStack(spacing: 10) {
                Text(format == .encryptedBackup ? "\u{1F512}" : "\u{1F4C4}")
                    .font(.system(size: 14))
                VStack(alignment: .leading, spacing: 2) {
                    Text(format.rawValue)
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundColor(theme.text)
                    Text(format == .encryptedBackup
                         ? "AES-256-GCM encrypted, password protected"
                         : "Plaintext — not recommended for sensitive data")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(theme.textFaint)
                }
                Spacer()
                if isSelected {
                    Text("\u{25C9}")
                        .font(.system(size: 14))
                        .foregroundColor(theme.accentBlue)
                } else {
                    Text("\u{25CB}")
                        .font(.system(size: 14))
                        .foregroundColor(theme.textGhost)
                }
            }
            .padding(10)
            .background(isSelected ? theme.activeBg : theme.fieldBg)
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isSelected ? theme.focusBorder : theme.inputBorder, lineWidth: 1)
            )
        }
        .buttonStyle(.hand)
    }

    // MARK: - Encrypted Backup

    private var encryptedBackupSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Set a password for this backup. You\u{2019}ll need it to restore.")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(theme.textSecondary)

            ZStack(alignment: .leading) {
                if vault.exportPasswordInput.isEmpty {
                    Text("Export password")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.textMuted)
                        .padding(10)
                }
                SecureField("", text: $vault.exportPasswordInput)
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

            ZStack(alignment: .leading) {
                if vault.exportPasswordConfirm.isEmpty {
                    Text("Confirm password")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.textMuted)
                        .padding(10)
                }
                SecureField("", text: $vault.exportPasswordConfirm)
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

            // Password strength hint
            if !vault.exportPasswordInput.isEmpty {
                passwordStrengthBar(vault.exportPasswordInput)
            }

            // Action buttons
            exportButtons {
                vault.exportEncryptedBackup()
            }
        }
    }

    // MARK: - CSV Export

    private var csvSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Warning — always visible
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text("\u{26A0}\u{FE0F}")
                        .font(.system(size: 14))
                    Text("Danger: Unencrypted export")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundColor(theme.accentRed)
                }
                Text("All passwords, card numbers, CVVs, and notes will be saved as plaintext. Any app on your computer can read this file. Delete it immediately after use.")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.accentYellow)
            }
            .padding(10)
            .background(theme.accentRed.opacity(0.08))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(theme.accentRed.opacity(0.3), lineWidth: 1)
            )

            if !vault.csvExportConfirmed {
                // Step 1: Explicit confirmation
                Button(action: { vault.csvExportConfirmed = true }) {
                    Text("I understand, proceed with plaintext export")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundColor(theme.accentRed)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(theme.accentRed.opacity(0.1))
                        .cornerRadius(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(theme.accentRed.opacity(0.3), lineWidth: 1)
                        )
                }
                .buttonStyle(.hand)
            } else {
                // Step 2: Master password re-entry
                Text("Enter your master password to confirm export.")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.textSecondary)

                ZStack(alignment: .leading) {
                    if vault.csvExportMasterPassword.isEmpty {
                        Text("Master password")
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundColor(theme.textMuted)
                            .padding(10)
                    }
                    SecureField("", text: $vault.csvExportMasterPassword)
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
                .onSubmit { vault.exportCSV() }

                // Action buttons
                exportButtons {
                    vault.exportCSV()
                }
            }
        }
    }

    // MARK: - Shared Buttons

    private func exportButtons(action: @escaping () -> Void) -> some View {
        HStack(spacing: 8) {
            Button(action: { vault.cancelExport() }) {
                Text("Cancel")
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundColor(theme.textSecondary)
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

            Button(action: action) {
                HStack(spacing: 6) {
                    if vault.isExporting {
                        ProgressView()
                            .scaleEffect(0.7)
                            .progressViewStyle(.circular)
                        Text("Exporting\u{2026}")
                            .font(.system(size: 13, weight: .semibold))
                    } else {
                        Image(systemName: "square.and.arrow.up")
                            .font(.system(size: 12))
                        Text("Export")
                            .font(.system(size: 13, weight: .semibold))
                    }
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(
                    LinearGradient(
                        colors: [Color(hex: "3b82f6"), Color(hex: "2563eb")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .cornerRadius(8)
            }
            .buttonStyle(.hand)
            .disabled(vault.isExporting)
        }
    }

    // MARK: - Password Strength

    private func passwordStrengthBar(_ password: String) -> some View {
        let strength = passwordStrength(password)
        return HStack(spacing: 8) {
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(theme.fieldBg)
                        .frame(height: 4)
                    RoundedRectangle(cornerRadius: 2)
                        .fill(strength.color)
                        .frame(width: geo.size.width * strength.fraction, height: 4)
                }
            }
            .frame(height: 4)
            Text(strength.label)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(strength.color)
                .frame(width: 50, alignment: .trailing)
        }
    }

    private struct PasswordStrength {
        let label: String
        let color: Color
        let fraction: CGFloat
    }

    private func passwordStrength(_ pw: String) -> PasswordStrength {
        var score = 0
        if pw.count >= 8 { score += 1 }
        if pw.count >= 12 { score += 1 }
        if pw.rangeOfCharacter(from: .uppercaseLetters) != nil { score += 1 }
        if pw.rangeOfCharacter(from: .decimalDigits) != nil { score += 1 }
        if pw.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) != nil { score += 1 }

        switch score {
        case 0...1: return PasswordStrength(label: "Weak", color: Color(hex: "ef4444"), fraction: 0.2)
        case 2: return PasswordStrength(label: "Fair", color: Color(hex: "f59e0b"), fraction: 0.4)
        case 3: return PasswordStrength(label: "Good", color: Color(hex: "eab308"), fraction: 0.6)
        case 4: return PasswordStrength(label: "Strong", color: Color(hex: "22c55e"), fraction: 0.8)
        default: return PasswordStrength(label: "Great", color: Color(hex: "10b981"), fraction: 1.0)
        }
    }
}
