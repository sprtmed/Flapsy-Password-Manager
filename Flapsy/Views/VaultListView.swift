import SwiftUI

struct VaultListView: View {
    @EnvironmentObject var vault: VaultViewModel
    @EnvironmentObject var settings: SettingsViewModel
    @EnvironmentObject var updateCheck: UpdateCheckService
    @Environment(\.theme) var theme

    @FocusState private var isSearchFieldFocused: Bool
    @State private var keyMonitor: Any?

    var body: some View {
        VStack(spacing: 0) {
            if vault.showExpandedNote {
                // Expanded note takes over the full space
                ItemDetailView()
            } else {
                searchBar
                typeFilterRow
                categoryFilterRow
                sortRow
                itemList

                if vault.selectedItem != nil {
                    ItemDetailView()
                }

                Spacer(minLength: 0)

                footer
            }

            // Hidden Cmd+K handler
            Button("") { vault.isSearchFocused = true }
                .keyboardShortcut("k", modifiers: .command)
                .frame(width: 0, height: 0)
                .opacity(0)
        }
        .onAppear {
            installKeyMonitor()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                isSearchFieldFocused = true
            }
        }
        .onDisappear { removeKeyMonitor() }
        .onChange(of: vault.isSearchFocused) { focused in
            if focused {
                isSearchFieldFocused = true
                vault.isSearchFocused = false
            }
        }
    }

    // MARK: - Keyboard Navigation

    private func installKeyMonitor() {
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            // Only handle when vault list is the active panel
            guard vault.currentPanel == .list else { return event }

            switch Int(event.keyCode) {
            case 125: // Down arrow
                navigateList(direction: 1)
                return nil
            case 126: // Up arrow
                navigateList(direction: -1)
                return nil
            case 36: // Return/Enter
                if vault.isEditingItem { return event }
                if vault.selectedItemID != nil {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        vault.selectedItemID = nil
                        vault.showPassword = false
                        vault.showCardNumber = false
                        vault.showCVV = false
                        vault.isEditingItem = false
                    }
                } else if let first = vault.filteredItems.first {
                    withAnimation(.easeInOut(duration: 0.15)) { selectItem(first.id) }
                }
                return nil
            case 53: // Escape
                if vault.selectedItemID != nil {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        vault.selectedItemID = nil
                        vault.showPassword = false
                        vault.showCardNumber = false
                        vault.showCVV = false
                        vault.isEditingItem = false
                    }
                    return nil
                }
                return event
            default:
                return event
            }
        }
    }

    private func removeKeyMonitor() {
        if let monitor = keyMonitor {
            NSEvent.removeMonitor(monitor)
            keyMonitor = nil
        }
    }

    private func navigateList(direction: Int) {
        let items = vault.filteredItems
        guard !items.isEmpty else { return }

        guard let currentID = vault.selectedItemID,
              let idx = items.firstIndex(where: { $0.id == currentID }) else {
            // Nothing selected — pick first (down) or last (up)
            let target = direction > 0 ? items.first! : items.last!
            withAnimation(.easeInOut(duration: 0.15)) { selectItem(target.id) }
            return
        }

        let next = idx + direction
        guard items.indices.contains(next) else { return }
        withAnimation(.easeInOut(duration: 0.15)) { selectItem(items[next].id) }
    }

    private func selectItem(_ id: UUID) {
        vault.selectedItemID = id
        vault.showPassword = false
        vault.showCardNumber = false
        vault.showCVV = false
        vault.isEditingItem = false
    }

    // MARK: - Search Bar

    private var searchBar: some View {
        HStack(spacing: 0) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15, weight: .medium))
                .foregroundColor(theme.textFaint)
                .padding(.leading, 10)

            ZStack(alignment: .leading) {
                if vault.searchText.isEmpty {
                    Text("Search vault\u{2026}  \u{2318}K")
                        .font(.ui(13))
                        .foregroundColor(theme.textSecondary)
                }
                TextField("", text: $vault.searchText)
                    .textFieldStyle(.plain)
                    .font(.ui(13))
                    .foregroundColor(theme.text)
                    .focused($isSearchFieldFocused)
            }
            .padding(10)

            if !vault.searchText.isEmpty {
                Button(action: { vault.searchText = "" }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 14))
                        .foregroundColor(theme.textSecondary)
                }
                .buttonStyle(.hand)
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
        .padding(.top, 10)
    }

    // MARK: - Type Filter

    private var typeFilterRow: some View {
        HStack(spacing: 3) {
            ScopeButton(icon: "square.grid.2x2", label: "All", isActive: vault.typeFilter == nil) {
                vault.typeFilter = nil
                vault.selectedItemID = nil
            }
            ScopeButton(icon: "key", label: "Logins", isActive: vault.typeFilter == .login) {
                vault.typeFilter = .login
                vault.selectedItemID = nil
            }
            ScopeButton(icon: "creditcard", label: "Cards", isActive: vault.typeFilter == .card) {
                vault.typeFilter = .card
                vault.selectedItemID = nil
            }
            ScopeButton(icon: "doc.text", label: "Notes", isActive: vault.typeFilter == .note) {
                vault.typeFilter = .note
                vault.selectedItemID = nil
            }
        }
        .padding(3)
        .background(theme.fieldBg)
        .cornerRadius(11)
        .padding(.horizontal, 16)
        .padding(.top, 8)
    }

    // MARK: - Category Filter

    private var categoryFilterRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 2) {
                FilterPill(title: "\u{229E} All", isActive: vault.activeCategory == "all") {
                    vault.activeCategory = "all"
                    vault.selectedItemID = nil
                }
                Button(action: {
                    vault.showFavoritesOnly.toggle()
                    if vault.showFavoritesOnly {
                        vault.activeCategory = "all"
                    }
                    vault.selectedItemID = nil
                }) {
                    Text(vault.showFavoritesOnly ? "\u{2605}" : "\u{2606}")
                        .font(.system(size: 13))
                        .foregroundColor(vault.showFavoritesOnly ? Color(hex: "fbbf24") : theme.textMuted)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(vault.showFavoritesOnly ? theme.pillBg : Color.clear)
                        .cornerRadius(20)
                }
                .buttonStyle(.hand)
                ForEach(vault.categories) { cat in
                    CategoryPill(
                        label: cat.label,
                        colorHex: cat.color,
                        isActive: vault.activeCategory == cat.key
                    ) {
                        vault.activeCategory = cat.key
                        vault.selectedItemID = nil
                    }
                }
                Button(action: { vault.navigateToPanel(.tags) }) {
                    Text("\u{FF0B}")
                        .font(.system(size: 13))
                        .foregroundColor(theme.textFaint)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 5)
                }
                .buttonStyle(.hand)
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 8)
        .padding(.bottom, 6)
    }

    // MARK: - Sort

    private var sortRow: some View {
        HStack(spacing: 0) {
            Image(systemName: "arrow.up.arrow.down")
                .font(.system(size: 9, weight: .medium))
                .foregroundColor(theme.textGhost)
                .padding(.trailing, 4)
            ForEach(SortOption.allCases, id: \.self) { option in
                Button(action: { vault.sortOption = option }) {
                    Text(option.rawValue)
                        .font(.ui(10, weight: .medium))
                        .foregroundColor(vault.sortOption == option ? theme.accentBlueLt : theme.textGhost)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(vault.sortOption == option ? theme.pillBg : Color.clear)
                        .cornerRadius(10)
                }
                .buttonStyle(.hand)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 2)
    }

    // MARK: - Item List

    private var itemList: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(vault.filteredItems) { item in
                    VaultItemRow(item: item, searchQuery: vault.searchText)
                }
                if vault.filteredItems.isEmpty {
                    Text("No items found")
                        .font(.ui(12))
                        .foregroundColor(theme.textFaint)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 30)
                }
            }
        }
        .frame(maxHeight: vault.selectedItemID != nil ? 120 : .infinity)
        .layoutPriority(1)
    }

    // MARK: - Footer

    private var footer: some View {
        VStack(spacing: 4) {
            HStack {
                Text("\(vault.activeItems.count) items \u{00B7} AES-256 \u{00B7} v\(updateCheck.currentVersion)")
                    .font(.ui(10))
                    .foregroundColor(theme.textGhost)
                Spacer()
                if !vault.trashedItems.isEmpty {
                    Button(action: { vault.navigateToPanel(.trash) }) {
                        HStack(spacing: 3) {
                            Image(systemName: "trash")
                                .font(.system(size: 9))
                            Text("\(vault.trashedItems.count)")
                                .font(.ui(10))
                        }
                        .foregroundColor(theme.textGhost)
                    }
                    .buttonStyle(.hand)
                }
                Text("Auto-lock: \(settings.autoLockEnabled ? "\(Int(settings.autoLockMinutes))m" : "Off")")
                    .font(.ui(10))
                    .foregroundColor(theme.textGhost)
            }
            if updateCheck.updateAvailable, let version = updateCheck.latestVersion {
                Button(action: {
                    if let url = URL(string: "https://github.com/sprtmed/Flapsy-Password-Manager/releases/latest") {
                        NSWorkspace.shared.open(url)
                    }
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.down.circle")
                            .font(.system(size: 9))
                        Text("v\(version) available — download update")
                            .font(.ui(10))
                    }
                    .foregroundColor(theme.accentBlueLt)
                }
                .buttonStyle(.hand)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(theme.cardBorder)
                .frame(height: 1)
        }
    }
}

// MARK: - Vault Item Row

struct VaultItemRow: View {
    let item: VaultItem
    var searchQuery: String = ""
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @State private var isHovered = false

    private var isSelected: Bool {
        vault.selectedItemID == item.id
    }

    var body: some View {
        HStack(spacing: 10) {
            itemIcon

            VStack(alignment: .leading, spacing: 2) {
                highlightedText(item.name, query: searchQuery)
                    .font(.ui(13, weight: .semibold))
                    .foregroundColor(theme.text)
                    .lineLimit(1)
                highlightedText(item.subtitle, query: searchQuery)
                    .font(.mono(11))
                    .foregroundColor(theme.textFaint)
                    .lineLimit(1)
            }

            Spacer()

            if vault.compromisedItemIDs.contains(item.id) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 10))
                    .foregroundColor(theme.accentRed)
                    .help(healthTooltip)
            } else if vault.flaggedItemIDs.contains(item.id) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 10))
                    .foregroundColor(theme.accentYellow)
                    .help(healthTooltip)
            }

            if let age = item.passwordAge, age != .fresh {
                Image(systemName: "clock.badge.exclamationmark")
                    .font(.system(size: 10))
                    .foregroundColor(age == .old ? theme.accentRed : theme.accentYellow)
                    .help(passwordAgeTooltip)
            }

            Button(action: { vault.toggleFavorite(item.id) }) {
                Text(item.isFavorite ? "\u{2605}" : "\u{2606}")
                    .font(.system(size: 14))
                    .foregroundColor(item.isFavorite ? Color(hex: "fbbf24") : theme.textFaint)
            }
            .buttonStyle(.hand)

            VStack(alignment: .trailing, spacing: 3) {
                Text(item.lastUsedDisplay)
                    .font(.mono(10))
                    .foregroundColor(theme.textFaint)

                if item.type == .login, let password = item.password {
                    let strength = PasswordStrength.calculate(password)
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 2)
                            .fill(theme.fieldBg)
                            .frame(width: 36, height: 3)
                        RoundedRectangle(cornerRadius: 2)
                            .fill(PasswordStrength.color(for: strength))
                            .frame(width: 36 * CGFloat(strength) / 100, height: 3)
                    }
                    .frame(width: 36, height: 3)
                }
            }
        }
        .padding(.vertical, 9)
        .padding(.horizontal, 16)
        .background(isSelected ? theme.activeBg : (isHovered ? theme.hoverBg : Color.clear))
        .overlay(alignment: .leading) {
            Rectangle()
                .fill(isSelected ? theme.accentBlue : Color.clear)
                .frame(width: 2)
        }
        .overlay(alignment: .trailing) {
            if isHovered && hasQuickActions {
                quickActionBar
                    .padding(.trailing, 12)
                    .transition(.opacity)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            withAnimation(.easeInOut(duration: 0.15)) {
                vault.selectedItemID = isSelected ? nil : item.id
                vault.showPassword = false
                vault.showCardNumber = false
                vault.showCVV = false
                vault.isEditingItem = false
            }
        }
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.12)) { isHovered = hovering }
            if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
        }
        .onDisappear {
            if isHovered { NSCursor.pop(); isHovered = false }
        }
    }

    // MARK: - Hover Quick Actions

    private var hasUsername: Bool { !(item.username ?? "").isEmpty }
    private var hasPassword: Bool { !(item.password ?? "").isEmpty }
    private var hasURL: Bool { !(item.url ?? "").isEmpty }
    private var hasCardNumber: Bool { !(item.cardNumber ?? "").isEmpty }

    private var hasQuickActions: Bool {
        switch item.type {
        // Star toggle is always available, so logins and cards always get a toolbar.
        case .login, .card: return true
        case .note:         return false
        }
    }

    @ViewBuilder
    private var quickActionBar: some View {
        HStack(spacing: 4) {
            switch item.type {
            case .login:
                if hasUsername {
                    QuickIconButton(copied: vault.copiedField == "qa-user-\(item.id)", icon: "person", help: "Copy username") {
                        vault.copyToClipboard(item.username!, fieldName: "qa-user-\(item.id)")
                    }
                }
                if hasPassword {
                    QuickIconButton(copied: vault.copiedField == "qa-pass-\(item.id)", icon: "key", help: "Copy password") {
                        vault.copyToClipboard(item.password!, fieldName: "qa-pass-\(item.id)")
                    }
                }
                if hasURL {
                    QuickPrimaryButton(copied: false, label: "Open", icon: "arrow.up.right.square", help: "Open \(item.url!)") {
                        openItemURL()
                    }
                }
                QuickStarButton(isFavorite: item.isFavorite) { vault.toggleFavorite(item.id) }
            case .card:
                if hasCardNumber {
                    QuickPrimaryButton(copied: vault.copiedField == "qa-card-\(item.id)", label: "Copy number", icon: "doc.on.doc", help: "Copy card number") {
                        vault.copyToClipboard(item.cardNumber!, fieldName: "qa-card-\(item.id)")
                    }
                }
                QuickStarButton(isFavorite: item.isFavorite) { vault.toggleFavorite(item.id) }
            case .note:
                EmptyView()
            }
        }
        .padding(4)
        .background(
            RoundedRectangle(cornerRadius: 9)
                .fill(theme.cardBg)
                .overlay(
                    RoundedRectangle(cornerRadius: 9)
                        .stroke(theme.cardBorder, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.14), radius: 6, x: 0, y: 2)
        )
    }

    private func openItemURL() {
        guard let url = item.url, !url.isEmpty else { return }
        let urlString = url.hasPrefix("http://") || url.hasPrefix("https://") ? url : "https://\(url)"
        if let openURL = URL(string: urlString) {
            NSWorkspace.shared.open(openURL)
        }
    }

    private var healthTooltip: String {
        var issues: [String] = []
        if vault.compromisedItemIDs.contains(item.id) { issues.append("Breached password") }
        if vault.weakPasswordItemIDs.contains(item.id) { issues.append("Weak password") }
        if vault.reusedPasswordItemIDs.contains(item.id) { issues.append("Reused password") }
        if vault.duplicateLoginItemIDs.contains(item.id) { issues.append("Duplicate login") }
        return issues.joined(separator: ", ")
    }

    private var passwordAgeTooltip: String {
        guard let days = item.passwordAgeDays else { return "" }
        if days >= 365 {
            let years = days / 365
            return "Password unchanged for \(years) year\(years == 1 ? "" : "s")"
        }
        let months = days / 30
        return "Password unchanged for \(months) month\(months == 1 ? "" : "s")"
    }

    private var itemIcon: some View {
        let catColor = vault.categoryFor(key: item.category)?.color ?? "10b981"
        let colors = theme.categoryColors(hex: catColor)
        return ZStack {
            RoundedRectangle(cornerRadius: 10)
                .fill(colors.background)
                .frame(width: 36, height: 36)
            Group {
                switch item.type {
                case .card:
                    Text("\u{1F4B3}")
                        .font(.system(size: 16))
                case .note:
                    Text("\u{1F4DD}")
                        .font(.system(size: 16))
                case .login:
                    Circle()
                        .fill(colors.foreground)
                        .frame(width: 12, height: 12)
                }
            }
        }
    }

    // MARK: - Fuzzy Highlight

    private func highlightedText(_ fullText: String, query: String) -> Text {
        guard !query.isEmpty,
              let match = FuzzySearch.match(query: query, in: fullText) else {
            return Text(fullText)
        }

        let chars = Array(fullText)
        let matchedSet = Set(match.matchedIndices)
        var result = Text("")

        for (i, char) in chars.enumerated() {
            let charText = Text(String(char))
            if matchedSet.contains(i) {
                result = result + charText.foregroundColor(theme.accentBlueLt).bold()
            } else {
                result = result + charText
            }
        }
        return result
    }
}

// MARK: - Hover Quick-Action Buttons

/// Icon-only quick-action button (copy username / password).
/// On hover the glyph darkens from `textMuted` → `text`, matching the design's `.qbtn:hover`.
private struct QuickIconButton: View {
    let copied: Bool
    let icon: String
    let help: String
    let action: () -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: copied ? "checkmark" : icon)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(copied ? theme.accentGreen : (hovering ? theme.text : theme.textMuted))
                .frame(width: 28, height: 28)
                .background(copied ? theme.accentGreen.opacity(0.15) : theme.fieldBg)
                .cornerRadius(7)
        }
        .buttonStyle(.hand)
        .help(help)
        .onHover { hovering = $0 }
    }
}

/// Primary quick-action button (Open / Copy number).
/// On hover the background darkens from `accentBlue` → `accentInk`, matching `.qbtn.primary:hover`.
private struct QuickPrimaryButton: View {
    let copied: Bool
    let label: String
    let icon: String
    let help: String
    let action: () -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: copied ? "checkmark" : icon)
                    .font(.system(size: 11, weight: .semibold))
                Text(copied ? "Copied" : label)
                    .font(.ui(11, weight: .semibold))
            }
            .foregroundColor(.white)
            .padding(.horizontal, 10)
            .frame(height: 28)
            .background(hovering ? theme.accentInk : theme.accentBlue)
            .cornerRadius(7)
        }
        .buttonStyle(.hand)
        .help(help)
        .onHover { hovering = $0 }
    }
}

/// Favorite toggle inside the hover toolbar. Filled gold when favorited;
/// otherwise an outline that darkens `textMuted` → `text` on hover.
private struct QuickStarButton: View {
    let isFavorite: Bool
    let action: () -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: isFavorite ? "star.fill" : "star")
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(isFavorite ? Color(hex: "fbbf24") : (hovering ? theme.text : theme.textMuted))
                .frame(width: 28, height: 28)
                .background(theme.fieldBg)
                .cornerRadius(7)
        }
        .buttonStyle(.hand)
        .help(isFavorite ? "Remove from favorites" : "Add to favorites")
        .onHover { hovering = $0 }
    }
}

// MARK: - Scope Segmented Control

/// One segment of the type filter (All / Logins / Cards / Notes), matching the
/// design's `.scope`: icon + label, muted by default, white pill + accent icon when active.
private struct ScopeButton: View {
    let icon: String
    let label: String
    let isActive: Bool
    let action: () -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .regular))
                    .foregroundColor(isActive ? theme.accentBlue : (hovering ? theme.textMuted : theme.textFaint))
                Text(label)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(isActive || hovering ? theme.text : theme.textMuted)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(isActive ? theme.cardBg : Color.clear)
                    .shadow(color: isActive ? Color.black.opacity(0.10) : Color.clear, radius: 2, y: 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.hand)
        .onHover { hovering = $0 }
    }
}

// MARK: - Filter Pill

struct FilterPill: View {
    let title: String
    let isActive: Bool
    let action: () -> Void

    @Environment(\.theme) var theme

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.ui(11, weight: .medium))
                .foregroundColor(isActive ? theme.accentBlueLt : theme.textMuted)
                .fixedSize()
                .padding(.horizontal, 12)
                .padding(.vertical, 5)
                .background(isActive ? theme.pillBg : Color.clear)
                .cornerRadius(20)
        }
        .buttonStyle(.hand)
    }
}

// MARK: - Category Pill (with color dot)

struct CategoryPill: View {
    let label: String
    let colorHex: String
    let isActive: Bool
    let action: () -> Void

    @Environment(\.theme) var theme

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Circle()
                    .fill(Color(hex: colorHex))
                    .frame(width: 8, height: 8)
                Text(label)
                    .font(.ui(11, weight: .medium))
                    .foregroundColor(isActive ? theme.accentBlueLt : theme.textMuted)
            }
            .fixedSize()
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(isActive ? theme.pillBg : Color.clear)
            .cornerRadius(20)
        }
        .buttonStyle(.hand)
    }
}
