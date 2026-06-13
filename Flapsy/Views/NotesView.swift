import SwiftUI
import AppKit

/// Standalone Notes mini-app (like Pomodoro). Rich-text notes (bold/italic,
/// bullets, clickable links) whose list label is derived from the first line.
/// Notes are encrypted at rest in the same vault as everything else.
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

            if vault.noteEntries.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(vault.noteEntries) { entry in
                            NoteRow(entry: entry)
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
    let entry: NoteListEntry
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    private var note: Note { entry.note }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(note.displayTitle)
                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .foregroundColor(theme.text)
                    .lineLimit(1)
                    .truncationMode(.tail)

                secondaryLine
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

    @ViewBuilder
    private var secondaryLine: some View {
        if entry.match.isEmpty {
            if !entry.prefix.isEmpty {
                Text(entry.prefix)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.textFaint)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        } else {
            // Search snippet: highlight the matched substring in context.
            (
                Text(entry.prefix).foregroundColor(theme.textFaint)
                + Text(entry.match).foregroundColor(theme.accentBlueLt).bold()
                + Text(entry.suffix).foregroundColor(theme.textFaint)
            )
            .font(.system(size: 11, design: .monospaced))
            .lineLimit(2)
            .truncationMode(.tail)
        }
    }
}

// MARK: - Note Editor

private struct NoteEditorView: View {
    let noteID: UUID
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme
    @StateObject private var controller = RichTextController()

    private var note: Note? { vault.notes.first(where: { $0.id == noteID }) }

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

                Text(note?.dateDisplay ?? "")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(theme.textGhost)

                Button(action: { vault.deleteNote(noteID) }) {
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

            // Rich-text editor
            RichTextEditor(
                controller: controller,
                initialRTF: note?.rtfData,
                initialPlain: note?.body ?? "",
                textColor: NSColor(theme.text),
                linkColor: NSColor(theme.accentBlueLt),
                onChange: { rtf, plain in
                    vault.updateNoteContent(noteID, rtfData: rtf, plainText: plain)
                }
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            // Subtle, toolbar-free formatting hint
            Text("\u{2318}B bold \u{00B7} \u{2318}I italic \u{00B7} start a line with \u{201C}- \u{201D} for a bullet \u{00B7} links are automatic")
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(theme.textGhost)
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .overlay(alignment: .top) {
                    Rectangle().fill(theme.cardBorder).frame(height: 1)
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

// MARK: - Rich Text Editor (NSTextView-backed)

/// Bridges SwiftUI buttons/state to the underlying NSTextView for formatting.
final class RichTextController: ObservableObject {
    weak var textView: NSTextView?

    func toggleBold() { applyTrait(.boldFontMask) }
    func toggleItalic() { applyTrait(.italicFontMask) }

    private func applyTrait(_ trait: NSFontTraitMask) {
        guard let tv = textView, let storage = tv.textStorage else { return }
        let fm = NSFontManager.shared
        let range = tv.selectedRange()

        if range.length == 0 {
            // No selection — flip the trait for subsequently typed text.
            let current = (tv.typingAttributes[.font] as? NSFont) ?? NSFont.systemFont(ofSize: 14)
            let has = fm.traits(of: current).contains(trait)
            let updated = has ? fm.convert(current, toNotHaveTrait: trait)
                              : fm.convert(current, toHaveTrait: trait)
            tv.typingAttributes[.font] = updated
            return
        }

        guard tv.shouldChangeText(in: range, replacementString: nil) else { return }
        storage.beginEditing()
        storage.enumerateAttribute(.font, in: range, options: []) { value, sub, _ in
            let font = (value as? NSFont) ?? NSFont.systemFont(ofSize: 14)
            let has = fm.traits(of: font).contains(trait)
            let updated = has ? fm.convert(font, toNotHaveTrait: trait)
                              : fm.convert(font, toHaveTrait: trait)
            storage.addAttribute(.font, value: updated, range: sub)
        }
        storage.endEditing()
        tv.didChangeText()
    }
}

/// NSTextView subclass that maps ⌘B / ⌘I to formatting actions.
final class FormattingTextView: NSTextView {
    var onBold: (() -> Void)?
    var onItalic: (() -> Void)?

    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if event.modifierFlags.contains(.command),
           let chars = event.charactersIgnoringModifiers?.lowercased() {
            if chars == "b" { onBold?(); return true }
            if chars == "i" { onItalic?(); return true }
        }
        return super.performKeyEquivalent(with: event)
    }
}

struct RichTextEditor: NSViewRepresentable {
    @ObservedObject var controller: RichTextController
    let initialRTF: Data?
    let initialPlain: String
    let textColor: NSColor
    let linkColor: NSColor
    let onChange: (Data, String) -> Void

    private static let defaultFont = NSFont.systemFont(ofSize: 14)

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let textView = FormattingTextView()
        textView.delegate = context.coordinator
        textView.isRichText = true
        textView.isEditable = true
        textView.isSelectable = true
        textView.allowsUndo = true
        textView.isAutomaticLinkDetectionEnabled = true
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.font = Self.defaultFont
        textView.textContainerInset = NSSize(width: 4, height: 8)
        textView.drawsBackground = false
        textView.backgroundColor = .clear
        textView.insertionPointColor = textColor
        textView.linkTextAttributes = [
            .foregroundColor: linkColor,
            .underlineStyle: NSUnderlineStyle.single.rawValue,
            .cursor: NSCursor.pointingHand
        ]
        textView.onBold = { [weak controller] in controller?.toggleBold() }
        textView.onItalic = { [weak controller] in controller?.toggleItalic() }

        textView.textStorage?.setAttributedString(context.coordinator.loadAttributed())
        textView.typingAttributes = [.font: Self.defaultFont, .foregroundColor: textColor]

        controller.textView = textView

        let scroll = NSScrollView()
        scroll.documentView = textView
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.borderType = .noBorder
        textView.minSize = NSSize(width: 0, height: 0)
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true

        // Focus the editor shortly after it appears.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            textView.window?.makeFirstResponder(textView)
        }

        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        guard let textView = nsView.documentView as? FormattingTextView else { return }
        textView.insertionPointColor = textColor
        textView.linkTextAttributes = [
            .foregroundColor: linkColor,
            .underlineStyle: NSUnderlineStyle.single.rawValue,
            .cursor: NSCursor.pointingHand
        ]
    }

    // MARK: Coordinator

    final class Coordinator: NSObject, NSTextViewDelegate {
        let parent: RichTextEditor

        init(_ parent: RichTextEditor) { self.parent = parent }

        /// Builds the initial attributed string, forcing the foreground color to
        /// the current theme so notes stay readable if the theme changes (we only
        /// support bold/italic/bullets/links — never custom text colors).
        func loadAttributed() -> NSAttributedString {
            if let data = parent.initialRTF,
               let attr = try? NSAttributedString(
                    data: data,
                    options: [.documentType: NSAttributedString.DocumentType.rtf],
                    documentAttributes: nil) {
                let mutable = NSMutableAttributedString(attributedString: attr)
                mutable.addAttribute(.foregroundColor, value: parent.textColor,
                                     range: NSRange(location: 0, length: mutable.length))
                return mutable
            }
            return NSAttributedString(
                string: parent.initialPlain,
                attributes: [.font: RichTextEditor.defaultFont, .foregroundColor: parent.textColor]
            )
        }

        /// Markdown-style auto-bullet: typing a space right after a lone "-" or
        /// "*" at the start of a line converts it into a "• " bullet.
        func textView(_ textView: NSTextView, shouldChangeTextIn range: NSRange, replacementString text: String?) -> Bool {
            guard text == " ", let storage = textView.textStorage else { return true }
            let ns = storage.string as NSString
            let lineRange = ns.lineRange(for: NSRange(location: range.location, length: 0))
            let lineStart = lineRange.location
            let lineSoFar = ns.substring(with: NSRange(location: lineStart, length: range.location - lineStart))
            guard lineSoFar == "-" || lineSoFar == "*" else { return true }

            let markerRange = NSRange(location: lineStart, length: 1)
            if textView.shouldChangeText(in: markerRange, replacementString: "\u{2022}\t") {
                storage.replaceCharacters(
                    in: markerRange,
                    with: NSAttributedString(string: "\u{2022}\t", attributes: textView.typingAttributes)
                )
                textView.didChangeText()
            }
            return false  // consume the space; the bullet already includes spacing
        }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView,
                  let storage = textView.textStorage else { return }
            let rtf = storage.rtf(
                from: NSRange(location: 0, length: storage.length),
                documentAttributes: [.documentType: NSAttributedString.DocumentType.rtf]
            ) ?? Data()
            parent.onChange(rtf, storage.string)
        }
    }
}
