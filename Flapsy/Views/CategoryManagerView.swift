import SwiftUI

struct CategoryManagerView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @State private var editingKey: String? = nil
    @State private var editLabel: String = ""
    @State private var editColor: String = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Existing categories
                VStack(spacing: 6) {
                    if vault.categories.isEmpty {
                        Text("No categories yet")
                            .font(.ui(12))
                            .foregroundColor(theme.textFaint)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 20)
                    }
                    ForEach(vault.categories) { cat in
                        if editingKey == cat.key {
                            editRow(cat)
                        } else {
                            categoryRow(cat)
                        }
                    }
                }

                Divider()
                    .background(theme.cardBorder)

                // Add new category
                VStack(alignment: .leading, spacing: 10) {
                    FormLabel("ADD NEW CATEGORY")

                    // Color picker bar
                    colorPicker(
                        selected: vault.newTagColor,
                        onChange: { vault.newTagColor = $0 }
                    )

                    // Name input + Add button
                    HStack(spacing: 6) {
                        FormTextField(
                            placeholder: "Category name\u{2026}",
                            text: $vault.newTagName
                        )
                        .onSubmit { vault.addCategory() }

                        Button(action: { vault.addCategory() }) {
                            Text("Add")
                                .font(.ui(11, weight: .semibold))
                                .foregroundColor(
                                    vault.newTagName.trimmingCharacters(in: .whitespaces).isEmpty
                                    ? theme.textGhost : theme.accentBlueLt
                                )
                                .padding(.horizontal, 16)
                                .padding(.vertical, 8)
                                .background(theme.fieldBg)
                                .cornerRadius(6)
                        }
                        .buttonStyle(.hand)
                        .disabled(vault.newTagName.trimmingCharacters(in: .whitespaces).isEmpty)
                        .opacity(vault.newTagName.trimmingCharacters(in: .whitespaces).isEmpty ? 0.5 : 1.0)
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
                    .buttonStyle(.hand)
                }
            }
        }
    }

    // MARK: - Category Row

    private func categoryRow(_ cat: VaultCategory) -> some View {
        let hasItems = vault.categoryHasItems(cat.key)
        return HStack(spacing: 10) {
            Circle()
                .fill(Color(hex: cat.color))
                .frame(width: 12, height: 12)
            Text(cat.label)
                .font(.ui(13))
                .foregroundColor(theme.text)
            Spacer()

            // Edit button
            Button(action: {
                editingKey = cat.key
                editLabel = cat.label
                editColor = cat.color
            }) {
                Text("\u{270E}")
                    .font(.system(size: 12))
                    .foregroundColor(theme.textSecondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(theme.fieldBg)
                    .cornerRadius(6)
            }
            .buttonStyle(.hand)

            // Delete button (only if no items)
            if !hasItems {
                Button(action: { vault.removeCategory(cat.key) }) {
                    Text("\u{2715}")
                        .font(.system(size: 13))
                        .foregroundColor(theme.accentRed)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(theme.fieldBg)
                        .cornerRadius(6)
                }
                .buttonStyle(.hand)
            }
        }
        .padding(12)
        .background(theme.fieldBg)
        .cornerRadius(8)
    }

    // MARK: - Edit Row

    private func editRow(_ cat: VaultCategory) -> some View {
        VStack(spacing: 8) {
            colorPicker(selected: editColor, onChange: { editColor = $0 })

            HStack(spacing: 6) {
                FormTextField(placeholder: "Name\u{2026}", text: $editLabel)
                    .onSubmit { saveEdit(cat.key) }

                Button(action: { saveEdit(cat.key) }) {
                    Text("Save")
                        .font(.ui(11, weight: .semibold))
                        .foregroundColor(theme.accentBlueLt)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(theme.accentBlue.opacity(0.1))
                        .cornerRadius(6)
                }
                .buttonStyle(.hand)

                Button(action: { editingKey = nil }) {
                    Text("\u{2715}")
                        .font(.system(size: 11))
                        .foregroundColor(theme.textMuted)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 8)
                        .background(theme.fieldBg)
                        .cornerRadius(6)
                }
                .buttonStyle(.hand)
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
        vault.updateCategory(key: key, newLabel: trimmed, newColor: editColor)
        editingKey = nil
    }
}
