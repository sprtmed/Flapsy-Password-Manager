import SwiftUI

struct ExpandedNoteView: View {
    @Binding var text: String
    let title: String
    let readOnly: Bool
    let onDismiss: () -> Void
    var onEdit: (() -> Void)? = nil
    var onSave: (() -> Void)? = nil
    var onCancel: (() -> Void)? = nil
    var onDelete: (() -> Void)? = nil
    @Environment(\.theme) var theme

    init(text: Binding<String>, title: String, readOnly: Bool = false, onDismiss: @escaping () -> Void, onEdit: (() -> Void)? = nil, onSave: (() -> Void)? = nil, onCancel: (() -> Void)? = nil, onDelete: (() -> Void)? = nil) {
        self._text = text
        self.title = title
        self.readOnly = readOnly
        self.onDismiss = onDismiss
        self.onEdit = onEdit
        self.onSave = onSave
        self.onCancel = onCancel
        self.onDelete = onDelete
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 8) {
                Button(action: onDismiss) {
                    HStack(spacing: 4) {
                        Text("\u{2190}")
                            .font(.system(size: 11))
                        Text("Back")
                            .font(.ui(11))
                    }
                    .foregroundColor(theme.textSecondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 5)
                    .background(theme.fieldBg)
                    .cornerRadius(6)
                }
                .buttonStyle(.hand)

                Spacer()

                FormLabel(title)

                if let onEdit = onEdit {
                    Button(action: onEdit) {
                        Text("\u{270E}")
                            .font(.system(size: 12))
                            .foregroundColor(theme.textSecondary)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(theme.fieldBg)
                            .cornerRadius(6)
                    }
                    .buttonStyle(.hand)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            if readOnly {
                ScrollView {
                    Text(text)
                        .font(.ui(13))
                        .foregroundColor(theme.text)
                        .lineSpacing(3)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                }
                .background(theme.fieldBg)
                .cornerRadius(8)
                .padding(.horizontal, 16)
                .padding(.bottom, 16)
            } else {
                // Full-height editor
                PlainTextEditor(text: $text, textColor: NSColor(theme.text), insertionPointColor: NSColor(theme.text))
                    .padding(10)
                    .background(theme.inputBg)
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(theme.inputBorder, lineWidth: 1)
                    )
                    .padding(.horizontal, 16)

                // Action buttons (same as edit form)
                if let onSave = onSave {
                    HStack(spacing: 8) {
                        Button(action: onSave) {
                            Text("Save")
                                .font(.ui(12, weight: .semibold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 8)
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

                        if let onCancel = onCancel {
                            Button(action: onCancel) {
                                Text("Cancel")
                                    .font(.ui(12))
                                    .foregroundColor(theme.textSecondary)
                                    .padding(.horizontal, 16)
                                    .padding(.vertical, 8)
                                    .background(theme.fieldBg)
                                    .cornerRadius(8)
                            }
                            .buttonStyle(.hand)
                        }

                        Spacer()

                        if let onDelete = onDelete {
                            Button(action: onDelete) {
                                Image(systemName: "trash")
                                    .font(.system(size: 11))
                                    .foregroundColor(theme.accentRed)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(theme.fieldBg)
                                    .cornerRadius(6)
                            }
                            .buttonStyle(.hand)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                    .padding(.bottom, 16)
                } else {
                    Spacer().frame(height: 16)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .transition(.move(edge: .trailing).combined(with: .opacity))
    }
}

struct NoteExpandButton: View {
    let action: () -> Void
    @Environment(\.theme) var theme

    var body: some View {
        Button(action: action) {
            Image(systemName: "arrow.up.left.and.arrow.down.right")
                .font(.system(size: 10))
                .foregroundColor(theme.textFaint)
                .padding(4)
                .background(theme.fieldBg)
                .cornerRadius(4)
        }
        .buttonStyle(.hand)
        .help("Expand note")
    }
}
