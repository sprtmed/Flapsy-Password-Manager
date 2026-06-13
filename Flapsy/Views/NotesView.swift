import SwiftUI

/// Standalone Notes mini-app (like Pomodoro). Plain-text, full-text-searchable
/// notes whose list label is derived from the first line. Notes are encrypted
/// at rest in the same vault as everything else.
struct NotesView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    var body: some View {
        Group {
            if let id = vault.selectedNoteID {
                NoteEditorView(noteID: id)
            } else {
                notesList
            }
        }
    }

    // MARK: - List

    private var notesList: some View {
        VStack(spacing: 0) {
            header

            if vault.showNoteSearch {
                searchBar
            }

            if vault.filteredNotes.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(vault.filteredNotes) { note in
                            NoteRow(note: note)
                            Rectangle()
                                .fill(theme.cardBorder)
                                .frame(height: 1)
                                .padding(.leading, 16)
                        }
                    }
                }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text("\(vault.notes.count) note\(vault.notes.count == 1 ? "" : "s")")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(theme.textGhost)

            Spacer()

            Button(action: {
                withAnimation(.easeInOut(duration: 0.15)) {
                    vault.showNoteSearch.toggle()
                    if !vault.showNoteSearch { vault.noteSearchText = "" }
                }
            }) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 12))
                    .foregroundColor(vault.showNoteSearch ? theme.accentBlueLt : theme.textSecondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(vault.showNoteSearch ? theme.pillBg : theme.fieldBg)
                    .cornerRadius(6)
            }
            .buttonStyle(.plain)
            .help("Search notes")

            Button(action: {
                withAnimation(.easeInOut(duration: 0.15)) { _ = vault.addNote() }
            }) {
                Image(systemName: "square.and.pencil")
                    .font(.system(size: 12))
                    .foregroundColor(theme.accentBlueLt)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(theme.accentBlue.opacity(0.1))
                    .cornerRadius(6)
            }
            .buttonStyle(.plain)
            .help("New note")
        }
        .padding(.horizontal, 16)
        .padding(.top, 10)
        .padding(.bottom, 8)
    }

    private var searchBar: some View {
        HStack(spacing: 0) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 14, weight: .medium))
                .foregroundColor(theme.textFaint)
                .padding(.leading, 10)

            ZStack(alignment: .leading) {
                if vault.noteSearchText.isEmpty {
                    Text("Search notes\u{2026}")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(theme.textSecondary)
                }
                TextField("", text: $vault.noteSearchText)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(theme.text)
            }
            .padding(10)

            if !vault.noteSearchText.isEmpty {
                Button(action: { vault.noteSearchText = "" }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 14))
                        .foregroundColor(theme.textSecondary)
                }
                .buttonStyle(.plain)
                .padding(.trailing, 10)
            }
        }
        .background(theme.inputBg)
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(theme.inputBorder, lineWidth: 1)
        )
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Spacer()
            Image(systemName: "note.text")
                .font(.system(size: 32))
                .foregroundColor(theme.textGhost)
            Text(vault.noteSearchText.isEmpty ? "No notes yet" : "No matching notes")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(theme.textFaint)
            if vault.noteSearchText.isEmpty {
                Button(action: {
                    withAnimation(.easeInOut(duration: 0.15)) { _ = vault.addNote() }
                }) {
                    Text("+ New note")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundColor(theme.accentBlueLt)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 7)
                        .background(theme.accentBlue.opacity(0.1))
                        .cornerRadius(8)
                }
                .buttonStyle(.plain)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Note Row

private struct NoteRow: View {
    let note: Note
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(note.displayTitle)
                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .foregroundColor(theme.text)
                    .lineLimit(1)
                    .truncationMode(.tail)
                if !note.previewSubtitle.isEmpty {
                    Text(note.previewSubtitle)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(theme.textFaint)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }

            Spacer(minLength: 8)

            Text(note.dateDisplay)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(theme.textFaint)
                .fixedSize()
        }
        .padding(.vertical, 11)
        .padding(.horizontal, 16)
        .contentShape(Rectangle())
        .onTapGesture {
            withAnimation(.easeInOut(duration: 0.15)) {
                vault.selectedNoteID = note.id
            }
        }
        .contextMenu {
            Button(role: .destructive) {
                vault.deleteNote(note.id)
            } label: {
                Label("Delete Note", systemImage: "trash")
            }
        }
    }
}

// MARK: - Note Editor

private struct NoteEditorView: View {
    let noteID: UUID
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme
    @FocusState private var isFocused: Bool

    private var bodyBinding: Binding<String> {
        Binding(
            get: { vault.notes.first(where: { $0.id == noteID })?.body ?? "" },
            set: { vault.updateNoteBody(noteID, body: $0) }
        )
    }

    private var dateLabel: String {
        vault.notes.first(where: { $0.id == noteID })?.dateDisplay ?? ""
    }

    var body: some View {
        VStack(spacing: 0) {
            // Internal toolbar: back to the notes list + delete
            HStack(spacing: 8) {
                Button(action: { leaveEditor() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 11, weight: .semibold))
                        Text("Notes")
                            .font(.system(size: 12, design: .monospaced))
                    }
                    .foregroundColor(theme.textSecondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(theme.fieldBg)
                    .cornerRadius(6)
                }
                .buttonStyle(.plain)

                Spacer()

                Text(dateLabel)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(theme.textGhost)

                Button(action: {
                    vault.deleteNote(noteID)
                }) {
                    Image(systemName: "trash")
                        .font(.system(size: 12))
                        .foregroundColor(theme.accentRed)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(theme.fieldBg)
                        .cornerRadius(6)
                }
                .buttonStyle(.plain)
                .help("Delete note")
            }
            .padding(.horizontal, 16)
            .padding(.top, 10)
            .padding(.bottom, 8)

            Divider().background(theme.cardBorder)

            // Editor
            TextEditor(text: bodyBinding)
                .font(.system(size: 14, design: .monospaced))
                .foregroundColor(theme.text)
                .scrollContentBackground(.hidden)
                .background(theme.dropBg)
                .focused($isFocused)
                .padding(.horizontal, 12)
                .padding(.top, 8)
        }
        .onAppear {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                isFocused = true
            }
        }
        .onDisappear {
            vault.discardNoteIfEmpty(noteID)
        }
    }

    private func leaveEditor() {
        let id = noteID
        withAnimation(.easeInOut(duration: 0.15)) {
            vault.selectedNoteID = nil
        }
        vault.discardNoteIfEmpty(id)
    }
}
