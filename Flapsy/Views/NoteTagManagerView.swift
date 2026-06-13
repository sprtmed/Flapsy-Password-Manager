import SwiftUI

/// Manager for Notes-app tags. Mirrors `CategoryManagerView` so creating and
/// editing note tags works identically to vault categories (consistent UX).
struct NoteTagManagerView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @State private var editingKey: String? = nil
    @State private var editLabel: String = ""
    @State private var editColor: String = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Existing tags
                VStack(spacing: 6) {
                    if vault.noteTags.isEmpty {
                        Text("No tags yet")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(theme.textFaint)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 20)
                    }
                    ForEach(vault.noteTags) { tag in
                        if editingKey == tag.key {
                            editRow(tag)
                        } else {
                            tagRow(tag)
                        }
                    }
                }

                Divider()
                    .background(theme.cardBorder)

                // Add new tag
                VStack(alignment: .leading, spacing: 10) {
                    FormLabel("ADD NEW TAG")

                    colorPicker(
                        selected: vault.newNoteTagColor,
                        onChange: { vault.newNoteTagColor = $0 }
                    )

                    HStack(spacing: 6) {
                        FormTextField(
                            placeholder: "Tag name\u{2026}",
                            text: $vault.newNoteTagName
                        )
                        .onSubmit { vault.addNoteTag() }

                        Button(action: { vault.addNoteTag() }) {
                            Text("Add")
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundColor(
                                    vault.newNoteTagName.trimmingCharacters(in: .whitespaces).isEmpty
                                    ? theme.textGhost : theme.accentBlueLt
                                )
                                .padding(.horizontal, 16)
                                .padding(.vertical, 8)
                                .background(theme.fieldBg)
                                .cornerRadius(6)
                        }
                        .buttonStyle(.plain)
                        .disabled(vault.newNoteTagName.trimmingCharacters(in: .whitespaces).isEmpty)
                        .opacity(vault.newNoteTagName.trimmingCharacters(in: .whitespaces).isEmpty ? 0.5 : 1.0)
                    }
                }
            }
            .padding(16)
        }
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }

    // MARK: - Color Picker

    private func colorPicker(selected: String, onChange: @escaping (String) -> Void) -> some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 5) {
                ForEach(VaultCategory.availableColors, id: \.self) { hex in
                    Button(action: { onChange(hex) }) {
                        Circle()
                            .fill(Color(hex: hex))
                            .frame(width: 18, height: 18)
                            .overlay(
                                Circle()
                                    .stroke(selected == hex ? Color.white : Color.clear, lineWidth: 1.5)
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    // MARK: - Tag Row

    private func tagRow(_ tag: VaultCategory) -> some View {
        let hasNotes = vault.noteTagHasNotes(tag.key)
        return HStack(spacing: 10) {
            Circle()
                .fill(Color(hex: tag.color))
                .frame(width: 12, height: 12)
            Text(tag.label)
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(theme.text)
            Spacer()

            Button(action: {
                editingKey = tag.key
                editLabel = tag.label
                editColor = tag.color
            }) {
                Text("\u{270E}")
                    .font(.system(size: 12))
                    .foregroundColor(theme.textSecondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(theme.fieldBg)
                    .cornerRadius(6)
            }
            .buttonStyle(.plain)

            // Delete (only if no notes use this tag)
            if !hasNotes {
                Button(action: { vault.removeNoteTag(tag.key) }) {
                    Text("\u{2715}")
                        .font(.system(size: 13))
                        .foregroundColor(theme.accentRed)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(theme.fieldBg)
                        .cornerRadius(6)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(12)
        .background(theme.fieldBg)
        .cornerRadius(8)
    }

    // MARK: - Edit Row

    private func editRow(_ tag: VaultCategory) -> some View {
        VStack(spacing: 8) {
            colorPicker(selected: editColor, onChange: { editColor = $0 })

            HStack(spacing: 6) {
                FormTextField(placeholder: "Name\u{2026}", text: $editLabel)
                    .onSubmit { saveEdit(tag.key) }

                Button(action: { saveEdit(tag.key) }) {
                    Text("Save")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .foregroundColor(theme.accentBlueLt)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(theme.accentBlue.opacity(0.1))
                        .cornerRadius(6)
                }
                .buttonStyle(.plain)

                Button(action: { editingKey = nil }) {
                    Text("\u{2715}")
                        .font(.system(size: 11))
                        .foregroundColor(theme.textMuted)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 8)
                        .background(theme.fieldBg)
                        .cornerRadius(6)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(12)
        .background(theme.activeBg)
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(theme.focusBorder, lineWidth: 1)
        )
    }

    private func saveEdit(_ key: String) {
        let trimmed = editLabel.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        vault.updateNoteTag(key: key, newLabel: trimmed, newColor: editColor)
        editingKey = nil
    }
}
