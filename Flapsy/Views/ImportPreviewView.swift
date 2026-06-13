import SwiftUI

struct ImportPreviewView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @State private var backupPassword: String = ""

    private var isKnoxBackup: Bool {
        vault.importPreview?.format == .knoxBackup
    }

    private var needsDecryption: Bool {
        isKnoxBackup
            && (vault.importPreview?.items.isEmpty ?? true)
            && (vault.importPreview?.appNotes.isEmpty ?? true)
    }

    var body: some View {
        VStack(spacing: 16) {
            // Header
            HStack {
                Text("\u{1F4E5} Import Preview")
                    .font(.system(size: 14, weight: .bold, design: .monospaced))
                    .foregroundColor(theme.text)
                Spacer()
                Button(action: { vault.cancelImport() }) {
                    Text("\u{2715}")
                        .font(.system(size: 14))
                        .foregroundColor(theme.textMuted)
                }
                .buttonStyle(.plain)
            }

            if vault.isImporting && !needsDecryption {
                // Show progress during parsing or confirming
                importProgressSection
            } else if needsDecryption {
                // Knox backup needs password to decrypt
                backupPasswordSection
            } else if let preview = vault.importPreview, !preview.items.isEmpty || !preview.appNotes.isEmpty {
                // Show parsed item counts
                itemPreview(preview)
            }

            // Error message
            if !vault.importError.isEmpty {
                Text("\u{2715} \(vault.importError)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.accentRed)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(16)
    }

    // MARK: - Import Progress

    private var importProgressSection: some View {
        VStack(spacing: 14) {
            ProgressView()
                .scaleEffect(0.9)
                .progressViewStyle(.circular)

            Text(vault.importProgress.isEmpty ? "Importing\u{2026}" : vault.importProgress)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(theme.textSecondary)
                .animation(.none, value: vault.importProgress)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
    }

    // MARK: - Backup Password

    private var backupPasswordSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("This is an encrypted Flapsy backup. Enter the export password to decrypt it.")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(theme.textSecondary)

            ZStack(alignment: .leading) {
                if backupPassword.isEmpty {
                    Text("Backup password")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.textMuted)
                        .padding(10)
                }
                SecureField("", text: $backupPassword)
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
            .onSubmit { vault.decryptKnoxBackup(password: backupPassword) }

            Button(action: { vault.decryptKnoxBackup(password: backupPassword) }) {
                HStack(spacing: 6) {
                    if vault.isImporting {
                        ProgressView()
                            .scaleEffect(0.7)
                            .progressViewStyle(.circular)
                        Text("Decrypting\u{2026}")
                            .font(.system(size: 13, weight: .semibold))
                    } else {
                        Image(systemName: "lock.open.fill")
                            .font(.system(size: 12))
                        Text("Decrypt")
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
            .buttonStyle(.plain)
            .disabled(backupPassword.isEmpty || vault.isImporting)
        }
    }

    // MARK: - Item Preview

    private func itemPreview(_ preview: ImportService.ImportResult) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            // Format detected
            HStack(spacing: 8) {
                Text("Format:")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.textFaint)
                Text(preview.format.rawValue)
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundColor(theme.accentBlueLt)
            }

            // Item counts
            VStack(spacing: 6) {
                if preview.loginCount > 0 {
                    countRow(icon: "\u{1F511}", label: "Logins", count: preview.loginCount)
                }
                if preview.cardCount > 0 {
                    countRow(icon: "\u{1F4B3}", label: "Cards", count: preview.cardCount)
                }
                if preview.noteCount > 0 {
                    countRow(icon: "\u{1F4DD}", label: "Notes", count: preview.noteCount)
                }
                if preview.appNoteCount > 0 {
                    countRow(icon: "\u{1F5D2}", label: "App Notes", count: preview.appNoteCount)
                }
            }
            .padding(12)
            .background(theme.fieldBg)
            .cornerRadius(8)

            // Total
            let totalUnits = preview.totalCount + preview.appNoteCount
            Text("Found \(totalUnits) item\(totalUnits == 1 ? "" : "s") to import")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(theme.textSecondary)

            // Duplicate info
            let dupeCount = preview.totalCount - ImportService.shared.deduplicateItems(
                incoming: preview.items, existing: vault.items
            ).count
            if dupeCount > 0 {
                Text("\(dupeCount) duplicate\(dupeCount == 1 ? "" : "s") will be skipped")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.textMuted)
            }

            // Category picker
            categoryPicker

            // Action buttons
            HStack(spacing: 8) {
                Button(action: { vault.cancelImport() }) {
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
                .buttonStyle(.plain)
                .disabled(vault.isImporting)

                Button(action: { vault.confirmImport() }) {
                    Text("Import All")
                        .font(.system(size: 13, weight: .semibold))
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
                        .opacity(vault.isImporting ? 0.5 : 1.0)
                }
                .buttonStyle(.plain)
                .disabled(vault.isImporting)
            }
        }
    }

    // MARK: - Category Picker

    private var categoryPicker: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("ASSIGN CATEGORY")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundColor(theme.textFaint)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    // "Keep original" option
                    Button(action: { vault.importCategory = "" }) {
                        Text("Keep original")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(vault.importCategory.isEmpty ? theme.accentBlueLt : theme.textMuted)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 6)
                            .background(vault.importCategory.isEmpty ? theme.pillBg : Color.clear)
                            .cornerRadius(20)
                            .overlay(
                                RoundedRectangle(cornerRadius: 20)
                                    .stroke(
                                        vault.importCategory.isEmpty ? theme.accentBlue.opacity(0.27) : theme.inputBorder,
                                        lineWidth: 1
                                    )
                            )
                    }
                    .buttonStyle(.plain)

                    ForEach(vault.categories) { cat in
                        Button(action: { vault.importCategory = cat.key }) {
                            HStack(spacing: 5) {
                                Circle()
                                    .fill(Color(hex: cat.color))
                                    .frame(width: 8, height: 8)
                                Text(cat.label)
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundColor(vault.importCategory == cat.key ? theme.accentBlueLt : theme.textMuted)
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 6)
                            .background(vault.importCategory == cat.key ? theme.pillBg : Color.clear)
                            .cornerRadius(20)
                            .overlay(
                                RoundedRectangle(cornerRadius: 20)
                                    .stroke(
                                        vault.importCategory == cat.key ? theme.accentBlue.opacity(0.27) : theme.inputBorder,
                                        lineWidth: 1
                                    )
                            )
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }

    private func countRow(icon: String, label: String, count: Int) -> some View {
        HStack {
            Text(icon)
                .font(.system(size: 14))
            Text(label)
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(theme.text)
            Spacer()
            Text("\(count)")
                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                .foregroundColor(theme.accentBlueLt)
        }
    }
}
