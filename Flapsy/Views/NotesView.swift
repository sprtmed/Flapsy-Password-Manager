import SwiftUI
import AppKit

/// Standalone Notes mini-app (like Pomodoro). Rich-text notes (bold/italic,
/// bullets, clickable links) whose list label is derived from the first line.
/// Notes are encrypted at rest in the same vault as everything else.
struct NotesView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme
    @FocusState private var listSearchFocused: Bool

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

            tagFilterRow

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
        .onChange(of: vault.showNoteSearch) { isOn in
            if isOn { listSearchFocused = true }
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
                    .focused($listSearchFocused)
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

    private var tagFilterRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 2) {
                FilterPill(title: "All", isActive: vault.activeNoteTag == "all" && !vault.showNoteFavoritesOnly) {
                    vault.activeNoteTag = "all"
                    vault.showNoteFavoritesOnly = false
                }

                Button(action: {
                    vault.showNoteFavoritesOnly.toggle()
                    if vault.showNoteFavoritesOnly { vault.activeNoteTag = "all" }
                }) {
                    Text(vault.showNoteFavoritesOnly ? "\u{2605}" : "\u{2606}")
                        .font(.system(size: 13))
                        .foregroundColor(vault.showNoteFavoritesOnly ? Color(hex: "fbbf24") : theme.textMuted)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(vault.showNoteFavoritesOnly ? theme.pillBg : Color.clear)
                        .cornerRadius(20)
                }
                .buttonStyle(.plain)
                .help("Favorites only")

                ForEach(vault.noteTags) { tag in
                    CategoryPill(
                        label: tag.label,
                        colorHex: tag.color,
                        isActive: vault.activeNoteTag == tag.key
                    ) {
                        vault.activeNoteTag = tag.key
                        vault.showNoteFavoritesOnly = false
                    }
                }

                Button(action: { vault.navigateToPanel(.noteTags) }) {
                    Text("\u{FF0B}")
                        .font(.system(size: 13))
                        .foregroundColor(theme.textFaint)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 5)
                }
                .buttonStyle(.plain)
                .help("Manage tags")
            }
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 6)
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
                HStack(spacing: 6) {
                    if let key = note.tag, let tag = vault.noteTagFor(key: key) {
                        Circle()
                            .fill(Color(hex: tag.color))
                            .frame(width: 8, height: 8)
                    }
                    Text(note.displayTitle)
                        .font(.system(size: 14, weight: .semibold, design: .monospaced))
                        .foregroundColor(theme.text)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }

                secondaryLine
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 6) {
                Button(action: { vault.toggleNoteFavorite(note.id) }) {
                    Text(note.isFavorite ? "\u{2605}" : "\u{2606}")
                        .font(.system(size: 14))
                        .foregroundColor(note.isFavorite ? Color(hex: "fbbf24") : theme.textFaint)
                }
                .buttonStyle(.plain)
                .help(note.isFavorite ? "Unstar" : "Star")

                Text(note.dateDisplay)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.textFaint)
                    .fixedSize()
            }
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
    @State private var showInNoteSearch = false
    @State private var inNoteQuery = ""
    @FocusState private var inNoteSearchFocused: Bool

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

                Button(action: { vault.toggleNoteFavorite(noteID) }) {
                    Text((note?.isFavorite ?? false) ? "\u{2605}" : "\u{2606}")
                        .font(.system(size: 14))
                        .foregroundColor((note?.isFavorite ?? false) ? Color(hex: "fbbf24") : theme.textSecondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(theme.fieldBg)
                        .cornerRadius(6)
                }
                .buttonStyle(.plain)
                .help((note?.isFavorite ?? false) ? "Unstar" : "Star")

                tagMenu

                Spacer()

                Text(note?.dateDisplay ?? "")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(theme.textGhost)

                Button(action: { toggleInNoteSearch() }) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 12))
                        .foregroundColor(showInNoteSearch ? theme.accentBlueLt : theme.textSecondary)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(showInNoteSearch ? theme.pillBg : theme.fieldBg)
                        .cornerRadius(6)
                }
                .buttonStyle(.plain)
                .help("Find in note")

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

            if showInNoteSearch {
                inNoteSearchBar
            }

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
        .onChange(of: inNoteQuery) { query in
            controller.runSearch(query)
        }
        .onChange(of: showInNoteSearch) { isOn in
            if isOn { inNoteSearchFocused = true }
        }
        .onDisappear {
            controller.clearSearch()
            vault.discardNoteIfEmpty(noteID)
        }
    }

    private var tagMenu: some View {
        let current = note?.tag.flatMap { vault.noteTagFor(key: $0) }
        return Menu {
            Button(action: { vault.setNoteTag(noteID, tag: nil) }) {
                if note?.tag == nil { Label("None", systemImage: "checkmark") } else { Text("None") }
            }
            ForEach(vault.noteTags) { tag in
                Button(action: { vault.setNoteTag(noteID, tag: tag.key) }) {
                    if note?.tag == tag.key { Label(tag.label, systemImage: "checkmark") } else { Text(tag.label) }
                }
            }
        } label: {
            HStack(spacing: 4) {
                if let current = current {
                    Circle().fill(Color(hex: current.color)).frame(width: 7, height: 7)
                    Text(current.label)
                } else {
                    Image(systemName: "tag")
                    Text("Tag")
                }
            }
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(current == nil ? theme.textSecondary : theme.accentBlueLt)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(theme.fieldBg)
            .cornerRadius(6)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Tag this note")
    }

    private var inNoteSearchBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(theme.textFaint)

            TextField("Find in note\u{2026}", text: $inNoteQuery)
                .textFieldStyle(.plain)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(theme.text)
                .focused($inNoteSearchFocused)
                .onSubmit { controller.nextMatch() }

            if !inNoteQuery.isEmpty {
                Text(controller.matchCount == 0 ? "0/0" : "\(controller.currentMatch)/\(controller.matchCount)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(theme.textFaint)
                    .fixedSize()

                Button(action: { controller.previousMatch() }) {
                    Image(systemName: "chevron.up").font(.system(size: 11))
                        .foregroundColor(theme.textSecondary)
                }
                .buttonStyle(.plain)
                .disabled(controller.matchCount == 0)

                Button(action: { controller.nextMatch() }) {
                    Image(systemName: "chevron.down").font(.system(size: 11))
                        .foregroundColor(theme.textSecondary)
                }
                .buttonStyle(.plain)
                .disabled(controller.matchCount == 0)
            }

            Button(action: { closeInNoteSearch() }) {
                Image(systemName: "xmark.circle.fill").font(.system(size: 13))
                    .foregroundColor(theme.textSecondary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }

    private func toggleInNoteSearch() {
        withAnimation(.easeInOut(duration: 0.15)) {
            showInNoteSearch.toggle()
        }
        if !showInNoteSearch {
            inNoteQuery = ""
            controller.clearSearch()
        }
    }

    private func closeInNoteSearch() {
        withAnimation(.easeInOut(duration: 0.15)) {
            showInNoteSearch = false
        }
        inNoteQuery = ""
        controller.clearSearch()
    }

    private func leaveEditor() {
        let id = noteID
        controller.clearSearch()
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

    // MARK: In-note find

    /// Match count and current position, published so the editor can show "2/5".
    @Published var matchCount: Int = 0
    @Published var currentMatch: Int = 0   // 1-based; 0 when no matches
    private var matchRanges: [NSRange] = []

    func toggleBold() { applyTrait(.boldFontMask) }
    func toggleItalic() { applyTrait(.italicFontMask) }

    /// Highlights every occurrence of `query` (display-only temporary
    /// attributes, never written to the note) and scrolls to the first match.
    func runSearch(_ query: String) {
        guard let tv = textView, let lm = tv.layoutManager, let storage = tv.textStorage else { return }
        let full = NSRange(location: 0, length: storage.length)
        lm.removeTemporaryAttribute(.backgroundColor, forCharacterRange: full)
        matchRanges = []

        let trimmed = query
        guard !trimmed.isEmpty else {
            matchCount = 0; currentMatch = 0
            return
        }

        let text = tv.string as NSString
        var start = 0
        while start < text.length {
            let found = text.range(
                of: trimmed,
                options: [.caseInsensitive],
                range: NSRange(location: start, length: text.length - start)
            )
            if found.location == NSNotFound { break }
            matchRanges.append(found)
            start = found.location + max(found.length, 1)
        }

        matchCount = matchRanges.count
        currentMatch = matchRanges.isEmpty ? 0 : 1
        applyHighlights()
        if let first = matchRanges.first { tv.scrollRangeToVisible(first) }
    }

    func nextMatch() {
        guard !matchRanges.isEmpty else { return }
        currentMatch = currentMatch % matchRanges.count + 1
        applyHighlights()
        textView?.scrollRangeToVisible(matchRanges[currentMatch - 1])
    }

    func previousMatch() {
        guard !matchRanges.isEmpty else { return }
        currentMatch = currentMatch <= 1 ? matchRanges.count : currentMatch - 1
        applyHighlights()
        textView?.scrollRangeToVisible(matchRanges[currentMatch - 1])
    }

    func clearSearch() {
        guard let tv = textView, let lm = tv.layoutManager, let storage = tv.textStorage else { return }
        lm.removeTemporaryAttribute(.backgroundColor, forCharacterRange: NSRange(location: 0, length: storage.length))
        matchRanges = []
        matchCount = 0
        currentMatch = 0
    }

    private func applyHighlights() {
        guard let tv = textView, let lm = tv.layoutManager, let storage = tv.textStorage else { return }
        lm.removeTemporaryAttribute(.backgroundColor, forCharacterRange: NSRange(location: 0, length: storage.length))
        for (i, range) in matchRanges.enumerated() {
            let isCurrent = (i + 1) == currentMatch
            let color = isCurrent
                ? NSColor.systemOrange.withAlphaComponent(0.7)
                : NSColor.systemYellow.withAlphaComponent(0.4)
            lm.addTemporaryAttributes([.backgroundColor: color], forCharacterRange: range)
        }
    }

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
