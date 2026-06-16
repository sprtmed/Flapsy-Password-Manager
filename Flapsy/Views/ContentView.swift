import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vault: VaultViewModel
    @EnvironmentObject var settings: SettingsViewModel

    private var theme: FlapsyTheme {
        settings.isDarkMode ? .dark : .light
    }

    var body: some View {
        ZStack {
            theme.dropBg.ignoresSafeArea()

            switch vault.currentScreen {
            case .setup:
                OnboardingView()
                    .transition(.opacity.combined(with: .move(edge: .bottom)))
            case .lock:
                LockScreenView()
                    .transition(.opacity.combined(with: .move(edge: .bottom)))
            case .vault:
                VaultContainerView()
                    .transition(.opacity.combined(with: .move(edge: .bottom)))
            }

            // Secret Key overlay (shown after vault creation or v1→v2 migration)
            if vault.showSecretKey {
                SecretKeyOverlay()
                    .transition(.opacity)
            }

            // Transient toast (copy confirmations, etc.)
            if let toast = vault.toastMessage {
                VStack {
                    Spacer()
                    Text(toast)
                        .font(.ui(12, weight: .semibold))
                        .foregroundColor(theme.bg)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .background(theme.text)
                        .cornerRadius(10)
                        .shadow(color: Color.black.opacity(0.3), radius: 12, y: 4)
                        .padding(.bottom, 16)
                }
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .allowsHitTesting(false)
            }
        }
        .ignoresSafeArea(.container, edges: .top)
        .frame(minWidth: 320, maxWidth: 420, minHeight: 480, maxHeight: 650)
        .environment(\.theme, theme)
        .font(.system(.body))
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: vault.currentScreen)
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: vault.toastMessage)
    }
}

/// Identifies which header/list dropdown is open. Top-level so the list's sort
/// chip can drive the same menu system the + / … buttons use.
enum HeaderMenuKind: Hashable { case new, more, sort, todoScope }

/// Container for all vault panels (list, add, generator, tags, settings)
struct VaultContainerView: View {
    @EnvironmentObject var vault: VaultViewModel
    @EnvironmentObject var settings: SettingsViewModel
    @Environment(\.theme) var theme

    @State private var menuAnchors: [HeaderMenuKind: CGRect] = [:]
    @State private var taskAnchors: [UUID: CGRect] = [:]
    @State private var taskPickerDate = Date()

    var body: some View {
        ZStack(alignment: .topLeading) {
            VStack(spacing: 0) {
                // Top bar (hidden when expanded note is active)
                if !vault.showExpandedNote {
                    if vault.currentPanel == .list {
                        listHeader
                    } else {
                        subPanelBar
                    }
                }
                // Panel content
                panelContent
            }

            // Import preview overlay
            if vault.showImportPreview {
                overlaySheet {
                    ImportPreviewView()
                }
            }

            // Export overlay
            if vault.showExportSheet {
                overlaySheet {
                    ExportView()
                }
            }

            // Item detail / edit — a full-window panel that slides in from the right,
            // covering the list (matches the design mockup).
            if vault.selectedItem != nil {
                ItemDetailView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(theme.dropBg.ignoresSafeArea())
                    .transition(.move(edge: .trailing))
                    .zIndex(20)
            }

            // Header dropdown menus (+ / …) — anchored under the button that opened them.
            if let menu = vault.openHeaderMenu {
                Color.clear
                    .contentShape(Rectangle())
                    .ignoresSafeArea()
                    .onTapGesture { withAnimation(.easeOut(duration: 0.1)) { vault.openHeaderMenu = nil } }

                GeometryReader { geo in
                    let anchor = menuAnchors[menu] ?? .zero
                    let menuWidth: CGFloat = 240
                    let x = min(max(8, anchor.maxX - menuWidth), max(8, geo.size.width - menuWidth - 8))
                    headerMenu(menu)
                        .frame(width: menuWidth)
                        .offset(x: x, y: anchor.maxY + 4)
                        .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: .topTrailing)))
                }
            }

            // Per-task date / repeat dropdown — same anchored card system as the
            // header menus (no system popover chrome).
            if let id = vault.openTaskDateMenu, let task = vault.tasks.first(where: { $0.id == id }) {
                dropdownDimmer { vault.openTaskDateMenu = nil }
                GeometryReader { geo in
                    anchoredCard(taskAnchors[id] ?? .zero, width: 240, estHeight: 392, in: geo) {
                        TaskDateMenuCard(
                            task: task,
                            onSetDate: { vault.setTaskDue(id, $0); vault.openTaskDateMenu = nil },
                            onRepeat: { vault.setTaskRepeat(id, $0) },
                            onPickDate: {
                                taskPickerDate = task.due ?? Date()
                                vault.openTaskDateMenu = nil
                                vault.openTaskDatePicker = id
                            }
                        )
                    }
                }
            }

            // Per-task "Pick a date…" calendar — anchored card.
            if let id = vault.openTaskDatePicker, vault.tasks.contains(where: { $0.id == id }) {
                dropdownDimmer { vault.openTaskDatePicker = nil }
                GeometryReader { geo in
                    anchoredCard(taskAnchors[id] ?? .zero, width: 286, estHeight: 340, in: geo) {
                        DatePickerCard(date: $taskPickerDate) {
                            vault.setTaskDue(id, $0)
                            vault.openTaskDatePicker = nil
                        }
                    }
                }
            }

            // Date-scope "Pick a date…" calendar — anchored under the scope chip.
            if vault.showTodoScopeDatePicker {
                dropdownDimmer { vault.showTodoScopeDatePicker = false }
                GeometryReader { geo in
                    anchoredCard(menuAnchors[.todoScope] ?? .zero, width: 286, estHeight: 340, in: geo) {
                        DatePickerCard(date: $taskPickerDate) {
                            vault.todoScope = .pick($0)
                            vault.showTodoScopeDatePicker = false
                        }
                    }
                }
            }
        }
        .coordinateSpace(name: "vaultContainer")
        .onPreferenceChange(HeaderMenuAnchorKey.self) { menuAnchors = $0 }
        .onPreferenceChange(TaskMenuAnchorKey.self) { taskAnchors = $0 }
        .ignoresSafeArea(.container, edges: .top)
        .animation(.spring(response: 0.32, dampingFraction: 0.9), value: vault.selectedItemID)
        .onChange(of: vault.currentPanel) { _ in
            vault.showExpandedNote = false
            vault.openHeaderMenu = nil
            vault.openTaskDateMenu = nil
            vault.openTaskDatePicker = nil
        }
        .animation(.easeOut(duration: 0.12), value: vault.openTaskDateMenu)
        .animation(.easeOut(duration: 0.12), value: vault.openTaskDatePicker)
        .animation(.easeOut(duration: 0.12), value: vault.showTodoScopeDatePicker)
    }

    /// Full-bleed transparent layer that dismisses an open dropdown on outside tap.
    private func dropdownDimmer(_ dismiss: @escaping () -> Void) -> some View {
        Color.clear
            .contentShape(Rectangle())
            .ignoresSafeArea()
            .onTapGesture { withAnimation(.easeOut(duration: 0.1)) { dismiss() } }
    }

    /// Positions a card beneath an anchor (right-aligned), flipping above it when it
    /// would overflow the bottom. Mirrors the header-menu placement.
    private func anchoredCard<C: View>(_ anchor: CGRect, width: CGFloat, estHeight: CGFloat,
                                       in geo: GeometryProxy, @ViewBuilder content: () -> C) -> some View {
        let x = min(max(8, anchor.maxX - width), max(8, geo.size.width - width - 8))
        let below = anchor.maxY + 4
        let flipUp = below + estHeight > geo.size.height - 8 && anchor.minY - estHeight - 4 > 8
        let y = max(8, flipUp ? anchor.minY - estHeight - 4 : below)
        return content()
            .frame(width: width)
            .offset(x: x, y: y)
            .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: flipUp ? .bottom : .top)))
    }

    /// Reports a header button's frame (in the container's coordinate space) so a
    /// dropdown can be anchored directly beneath it.
    private func anchorReporter(_ kind: HeaderMenuKind) -> some View {
        GeometryReader { geo in
            Color.clear.preference(
                key: HeaderMenuAnchorKey.self,
                value: [kind: geo.frame(in: .named("vaultContainer"))]
            )
        }
    }

    private func overlaySheet<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        ZStack {
            theme.dropBg
                .ignoresSafeArea()
            ScrollView {
                content()
            }
        }
        .transition(.opacity.combined(with: .move(edge: .bottom)))
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: vault.showImportPreview)
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: vault.showExportSheet)
    }

    // MARK: - Main vault header (list panel)

    private var listHeader: some View {
        VStack(spacing: 0) {
          GeometryReader { geo in
            HStack(spacing: 11) {
                // Gradient crest — doubles as the lock control: shows an open padlock
                // while unlocked; click it to lock the vault. (No separate lock chip.)
                Button(action: { vault.lock() }) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 10)
                            .fill(
                                LinearGradient(
                                    colors: [theme.accentBlue, Color(hex: "8a6bea")],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 34, height: 34)
                            .shadow(color: theme.accentBlue.opacity(0.4), radius: 3, y: 2)
                        Image(systemName: "lock.open.fill")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundColor(.white)
                    }
                }
                .buttonStyle(.hand)
                .help("Unlocked — click to lock")

                // Show the name only when the header is wide enough to fit it; in the
                // narrow window it's removed entirely (not truncated). geo is the
                // header's actual laid-out width, so this adapts to the icon count too.
                if geo.size.width >= 350 {
                    Text("Flapsy")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundColor(theme.text)
                        .lineLimit(1)
                        .fixedSize()
                }

                Spacer(minLength: 6)

                // Action buttons
                HStack(spacing: 2) {
                    HeaderIconButton(systemName: "plus", help: "New item") {
                        toggleMenu(.new)
                    }
                    .background(anchorReporter(.new))

                    if settings.showNotesInTopBar {
                        HeaderIconButton(systemName: "note.text", help: "Notes") {
                            vault.openHeaderMenu = nil
                            vault.navigateToPanel(.notes)
                        }
                    }

                    if settings.showTodoInTopBar {
                        HeaderIconButton(systemName: "checklist", help: "To-Do") {
                            vault.openHeaderMenu = nil
                            vault.navigateToPanel(.todo)
                        }
                    }

                    HeaderIconButton(systemName: "gearshape", help: "Settings") {
                        vault.openHeaderMenu = nil
                        vault.navigateToPanel(.settings)
                    }

                    HeaderIconButton(
                        systemName: settings.isWindowPinned ? "pin.fill" : "pin",
                        help: settings.isWindowPinned ? "Unpin window" : "Pin window",
                        isActive: settings.isWindowPinned,
                        activeColor: theme.accentYellow
                    ) {
                        vault.openHeaderMenu = nil
                        withAnimation(.spring(response: 0.2, dampingFraction: 0.7)) {
                            settings.isWindowPinned.toggle()
                        }
                    }

                    HeaderIconButton(systemName: "ellipsis", help: "More", showAlert: !vault.flaggedItemIDs.isEmpty) {
                        toggleMenu(.more)
                    }
                    .background(anchorReporter(.more))
                }
            }
            .frame(width: geo.size.width, height: 34)
          }
          .frame(height: 34)
          .padding(.horizontal, 14)
          .padding(.top, 13)
          .padding(.bottom, 12)

            Rectangle()
                .fill(theme.cardBorder)
                .frame(height: 1)
        }
        .padding(.top, 8)
    }

    private func toggleMenu(_ kind: HeaderMenuKind) {
        withAnimation(.easeOut(duration: 0.12)) {
            vault.openHeaderMenu = (vault.openHeaderMenu == kind) ? nil : kind
        }
    }

    // MARK: - Sub-panel bar (everything except the list)

    private var subPanelBar: some View {
        HStack {
            HStack(spacing: 8) {
                Image(systemName: "lock.open.fill")
                    .font(.system(size: 14))
                    .foregroundColor(theme.text)
                Text(panelTitle)
                    .font(.ui(14, weight: .bold))
                    .foregroundColor(theme.text)
            }
            Spacer()
            HStack(spacing: 4) {
                Button(action: { vault.navigateToPanel(vault.currentPanel == .noteTags ? .notes : .list) }) {
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

                if vault.currentPanel == .pomodoro {
                    Button(action: {
                        let pt = PomodoroTimer.shared
                        pt.stopAll()
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
                            pt.showBlockMode.toggle()
                        }
                    }) {
                        Image(systemName: "arrow.2.squarepath")
                            .font(.system(size: 11))
                            .foregroundColor(theme.accentBlue)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 5)
                            .background(theme.accentBlue.opacity(0.08))
                            .cornerRadius(6)
                    }
                    .buttonStyle(.hand)
                    .help(PomodoroTimer.shared.showBlockMode ? "Switch to Classic" : "Switch to Block Mode")
                }
            }
            .fixedSize()
        }
        .padding(.horizontal, 16)
        .frame(height: 30)
        .padding(.top, 12)
        .padding(.bottom, 6)
    }

    // MARK: - Header dropdown menus

    @ViewBuilder
    private func headerMenu(_ kind: HeaderMenuKind) -> some View {
        VStack(spacing: 2) {
            switch kind {
            case .new:
                HeaderMenuItem(icon: "key", label: "New login") {
                    selectMenu { vault.navigateToPanel(.addNew); vault.newType = .login }
                }
                HeaderMenuItem(icon: "creditcard", label: "New card") {
                    selectMenu { vault.navigateToPanel(.addNew); vault.newType = .card }
                }
                HeaderMenuItem(icon: "doc.text", label: "New secure note") {
                    selectMenu { vault.navigateToPanel(.addNew); vault.newType = .note }
                }
                HeaderMenuDivider()
                HeaderMenuItem(icon: "wand.and.stars", label: "Password generator") {
                    selectMenu { vault.navigateToPanel(.generator) }
                }
            case .more:
                HeaderMenuItem(icon: "shield.lefthalf.filled", label: "Security checkup",
                               badge: vault.flaggedItemIDs.isEmpty ? nil : "\(vault.flaggedItemIDs.count)") {
                    selectMenu { vault.navigateToPanel(.health) }
                }
                HeaderMenuItem(icon: "wand.and.stars", label: "Password generator") {
                    selectMenu { vault.navigateToPanel(.generator) }
                }
                HeaderMenuItem(icon: "tag", label: "Categories") {
                    selectMenu { vault.navigateToPanel(.tags) }
                }
                if !settings.showNotesInTopBar {
                    HeaderMenuItem(icon: "note.text", label: "Notes") {
                        selectMenu { vault.navigateToPanel(.notes) }
                    }
                }
                if !settings.showTodoInTopBar {
                    HeaderMenuItem(icon: "checklist", label: "To-Do") {
                        selectMenu { vault.navigateToPanel(.todo) }
                    }
                }
                HeaderMenuItem(icon: "timer", label: "Pomodoro") {
                    selectMenu { vault.navigateToPanel(.pomodoro) }
                }
                HeaderMenuDivider()
                HeaderMenuItem(icon: "trash", label: "Trash",
                               badge: vault.trashedItems.isEmpty ? nil : "\(vault.trashedItems.count)") {
                    selectMenu { vault.navigateToPanel(.trash) }
                }
            case .sort:
                ForEach(SortOption.allCases, id: \.self) { option in
                    HeaderMenuItem(label: option.rawValue, selected: vault.sortOption == option) {
                        selectMenu { vault.sortOption = option }
                    }
                }
            case .todoScope:
                HeaderMenuItem(label: "Anytime", selected: vault.todoScope == .anytime) { selectMenu { vault.todoScope = .anytime } }
                HeaderMenuItem(label: "Today", selected: vault.todoScope == .today) { selectMenu { vault.todoScope = .today } }
                HeaderMenuItem(label: "Tomorrow", selected: vault.todoScope == .tomorrow) { selectMenu { vault.todoScope = .tomorrow } }
                HeaderMenuItem(label: "This weekend", selected: vault.todoScope == .thisWeekend) { selectMenu { vault.todoScope = .thisWeekend } }
                HeaderMenuItem(label: "Next week", selected: vault.todoScope == .nextWeek) { selectMenu { vault.todoScope = .nextWeek } }
                HeaderMenuItem(label: "Overdue", selected: vault.todoScope == .overdue) { selectMenu { vault.todoScope = .overdue } }
                HeaderMenuItem(label: "No date", selected: vault.todoScope == .noDate) { selectMenu { vault.todoScope = .noDate } }
            }
        }
        .padding(5)
        .frame(width: 240)
        .background(theme.ddBg)
        .cornerRadius(11)
        .overlay(
            RoundedRectangle(cornerRadius: 11)
                .stroke(theme.ddBorder, lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.28), radius: 18, x: 0, y: 10)
    }

    private func selectMenu(_ action: () -> Void) {
        action()
        vault.openHeaderMenu = nil
    }

    @ViewBuilder
    private var panelContent: some View {
        switch vault.currentPanel {
        case .list:
            VaultListView()
        case .addNew:
            AddItemView()
        case .generator:
            GeneratorView()
        case .tags:
            CategoryManagerView()
        case .settings:
            SettingsView()
        case .health:
            VaultHealthView()
        case .pomodoro:
            PomodoroView()
        case .notes:
            NotesView()
        case .noteTags:
            NoteTagManagerView()
        case .trash:
            TrashView()
        case .todo:
            TodoView()
        }
    }

    private var panelTitle: String {
        switch vault.currentPanel {
        case .list: return "Vault"
        case .addNew: return "New Item"
        case .generator: return "Generator"
        case .tags: return "Categories"
        case .settings: return "Settings"
        case .health: return "Health"
        case .pomodoro: return "Pomodoro"
        case .notes: return "Notes"
        case .noteTags: return "Tags"
        case .trash: return "Trash"
        case .todo: return "To-Do"
        }
    }
}

// MARK: - Header Menu Anchoring

/// Captures header button frames so a dropdown can open directly beneath the
/// button that triggered it.
struct HeaderMenuAnchorKey: PreferenceKey {
    static var defaultValue: [HeaderMenuKind: CGRect] = [:]
    static func reduce(
        value: inout [HeaderMenuKind: CGRect],
        nextValue: () -> [HeaderMenuKind: CGRect]
    ) {
        value.merge(nextValue()) { $1 }
    }
}

// MARK: - Header Components

/// 30×30 transparent icon button matching the design's `.iconbtn` (muted icon,
/// field background + ink icon on hover). Optional warning alert dot.
private struct HeaderIconButton: View {
    let systemName: String
    let help: String
    var showAlert: Bool = false
    var isActive: Bool = false
    var activeColor: Color? = nil
    let action: () -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false

    var body: some View {
        let tint = activeColor ?? theme.accentBlue
        return Button(action: action) {
            ZStack(alignment: .topTrailing) {
                RoundedRectangle(cornerRadius: 8)
                    .fill(isActive ? tint.opacity(0.14) : (hovering ? theme.fieldBg : Color.clear))
                    .frame(width: 30, height: 30)
                    .overlay(
                        Image(systemName: systemName)
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(isActive ? tint : (hovering ? theme.text : theme.textMuted))
                    )
                if showAlert {
                    Circle()
                        .fill(theme.accentYellow)
                        .frame(width: 7, height: 7)
                        .overlay(Circle().stroke(theme.dropBg, lineWidth: 1.5))
                        .offset(x: -4, y: 4)
                }
            }
            .frame(width: 30, height: 30)
        }
        .buttonStyle(.hand)
        .help(help)
        .onHover { hovering = $0 }
    }
}

/// A row inside a header dropdown menu (icon + label, optional count badge).
private struct HeaderMenuItem: View {
    var icon: String? = nil
    let label: String
    var badge: String? = nil
    var selected: Bool = false
    let action: () -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                if let icon = icon {
                    Image(systemName: icon)
                        .font(.system(size: 13))
                        .foregroundColor(theme.textMuted)
                        .frame(width: 16)
                }
                Text(label)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundColor(theme.text)
                    .lineLimit(1)
                    .fixedSize()
                Spacer(minLength: 4)
                if let badge = badge {
                    Text(badge)
                        .font(.system(size: 10.5, weight: .bold))
                        .foregroundColor(theme.accentYellow)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(theme.accentYellow.opacity(0.16))
                        .cornerRadius(20)
                }
                if selected {
                    Image(systemName: "checkmark")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(theme.accentBlue)
                }
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(hovering ? theme.fieldBg : Color.clear)
            .cornerRadius(7)
            .contentShape(Rectangle())
        }
        .buttonStyle(.hand)
        .onHover { hovering = $0 }
    }
}

private struct HeaderMenuDivider: View {
    @Environment(\.theme) var theme
    var body: some View {
        Rectangle()
            .fill(theme.cardBorder)
            .frame(height: 1)
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
    }
}
