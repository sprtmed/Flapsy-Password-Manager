import SwiftUI

struct ItemDetailView: View {
    @EnvironmentObject var vault: VaultViewModel
    @EnvironmentObject var settings: SettingsViewModel
    @Environment(\.theme) var theme
    @State private var showDeleteConfirmation = false
    @State private var showMarkdownPreview = true

    private func dismissDetail() {
        withAnimation(.easeInOut(duration: 0.15)) {
            vault.selectedItemID = nil
            vault.showPassword = false
            vault.showCardNumber = false
            vault.showCVV = false
            vault.isEditingItem = false
        }
    }

    var body: some View {
        if let item = vault.selectedItem {
            if vault.isEditingItem {
                editView(item)
            } else if vault.showExpandedNote {
                readOnlyExpandedNote(item)
            } else {
                detailView(item)
            }
        }
        EmptyView()
            .onChange(of: vault.isEditingItem) { editing in
                if !editing {
                    vault.showExpandedNote = false
                    vault.expandedNoteAutoOpened = false
                }
            }
            .onChange(of: vault.selectedItemID) { newID in
                vault.showExpandedNote = false
                vault.expandedNoteAutoOpened = false
                // Auto-expand if setting is ON and item has notes
                if settings.alwaysExpandNotes, let id = newID, let item = vault.items.first(where: { $0.id == id }) {
                    let hasNotes: Bool = {
                        switch item.type {
                        case .login: return !(item.loginNotes ?? "").isEmpty
                        case .card: return !(item.cardNotes ?? "").isEmpty
                        case .note: return !(item.noteText ?? "").isEmpty
                        }
                    }()
                    if hasNotes {
                        vault.showExpandedNote = true
                    }
                }
            }
    }

    @ViewBuilder
    private func readOnlyExpandedNote(_ item: VaultItem) -> some View {
        let noteText: String = {
            switch item.type {
            case .login: return item.loginNotes ?? ""
            case .card: return item.cardNotes ?? ""
            case .note: return item.noteText ?? ""
            }
        }()
        ExpandedNoteView(
            text: .constant(noteText),
            title: item.type == .note ? "SECURE NOTE" : "NOTES",
            readOnly: true,
            onDismiss: {
                withAnimation(.easeInOut(duration: 0.15)) {
                    vault.showExpandedNote = false
                }
            },
            onEdit: {
                vault.requestEditWithReauth(item)
            }
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Detail View (read-only)

    private func detailView(_ item: VaultItem) -> some View {
        VStack(spacing: 0) {
            // Header bar: ← Vault · centered title · star + Edit
            HStack(spacing: 8) {
                backButton { dismissDetail() }

                Spacer(minLength: 4)

                Text(item.name)
                    .font(.ui(14, weight: .bold))
                    .foregroundColor(theme.text)
                    .lineLimit(1)

                Spacer(minLength: 4)

                Button(action: { vault.toggleFavorite(item.id) }) {
                    Image(systemName: item.isFavorite ? "star.fill" : "star")
                        .font(.system(size: 13))
                        .foregroundColor(item.isFavorite ? Color(hex: "fbbf24") : theme.textMuted)
                }
                .buttonStyle(.hand)

                Button(action: { vault.requestEditWithReauth(item) }) {
                    Text("Edit")
                        .font(.ui(12.5, weight: .semibold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 7)
                        .background(theme.accentBlue)
                        .cornerRadius(8)
                }
                .buttonStyle(.hand)
            }
            .padding(.horizontal, 12)
            .padding(.top, 16)
            .padding(.bottom, 11)
            .overlay(alignment: .bottom) {
                Rectangle().fill(theme.cardBorder).frame(height: 1)
            }

            // Body
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    // Centered hero: large avatar + name + subtitle
                    VStack(spacing: 9) {
                        ItemAvatar(item: item, size: 54)
                        Text(item.name)
                            .font(.ui(17, weight: .bold))
                            .foregroundColor(theme.text)
                            .multilineTextAlignment(.center)
                        if let subtitle = heroSubtitle(for: item) {
                            Text(subtitle)
                                .font(.mono(12.5))
                                .foregroundColor(theme.textMuted)
                                .multilineTextAlignment(.center)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.top, 4)
                    .padding(.bottom, 10)
                    .contentShape(Rectangle())
                    .onTapGesture { dismissDetail() }

                    // Health status banner (logins with security issues)
                    healthBanner(for: item, editing: false)

                    switch item.type {
                    case .login:
                        loginDetail(item)
                    case .card:
                        cardDetail(item)
                    case .note:
                        noteDetail(item)
                    }

                    // Tap empty space (anywhere but the fields) to close.
                    Color.clear
                        .frame(maxWidth: .infinity, minHeight: 140)
                        .contentShape(Rectangle())
                        .onTapGesture { dismissDetail() }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
            }

            // Footer: Modified … · Delete
            HStack {
                Text("Modified \(item.lastUsedDisplay)")
                    .font(.ui(11))
                    .foregroundColor(theme.textFaint)
                Spacer()
                Button(action: {
                    if settings.confirmBeforeDelete {
                        showDeleteConfirmation = true
                    } else {
                        vault.deleteItem(item.id)
                    }
                }) {
                    Text("Delete")
                        .font(.ui(12, weight: .semibold))
                        .foregroundColor(theme.accentRed)
                }
                .buttonStyle(.hand)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 11)
            .overlay(alignment: .top) {
                Rectangle().fill(theme.cardBorder).frame(height: 1)
            }
        }
        .alert("Delete Item", isPresented: $showDeleteConfirmation) {
            Button("Delete", role: .destructive) {
                vault.deleteItem(item.id)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Are you sure you want to delete \"\(item.name)\"?")
        }
        .overlay {
            if vault.showReauthPrompt {
                ReauthOverlay()
            }
        }
    }

    /// Subtitle shown under the name in the detail hero (URL for logins, type for cards).
    private func heroSubtitle(for item: VaultItem) -> String? {
        switch item.type {
        case .login:
            let url = item.url ?? ""
            return url.isEmpty ? nil : url
        case .card:
            let type = item.cardType ?? ""
            return type.isEmpty ? nil : type
        case .note:
            return nil
        }
    }

    /// Standard back button (← Back), matching the other panels.
    private func backButton(_ action: @escaping () -> Void) -> some View {
        Button(action: action) {
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
    }

    private func expandedNoteBinding(for item: VaultItem) -> Binding<String> {
        switch item.type {
        case .login: return $vault.editLoginNotes
        case .card: return $vault.editCardNotes
        case .note: return $vault.editNoteText
        }
    }

    // MARK: - Edit View

    @ViewBuilder
    private func editView(_ item: VaultItem) -> some View {
        if vault.showExpandedNote {
            ExpandedNoteView(
                text: expandedNoteBinding(for: item),
                title: item.type == .note ? "SECURE NOTE" : "NOTES",
                onDismiss: {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        vault.showExpandedNote = false
                    }
                },
                onSave: {
                    vault.saveEditedItem()
                },
                onCancel: {
                    vault.cancelEditing()
                },
                onDelete: {
                    if settings.confirmBeforeDelete {
                        showDeleteConfirmation = true
                    } else {
                        vault.deleteItem(item.id)
                        vault.isEditingItem = false
                    }
                }
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .transition(.move(edge: .trailing).combined(with: .opacity))
            .alert("Delete Item", isPresented: $showDeleteConfirmation) {
                Button("Delete", role: .destructive) {
                    vault.deleteItem(item.id)
                    vault.isEditingItem = false
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Are you sure you want to delete \"\(item.name)\"?")
            }
        } else {
            VStack(spacing: 0) {
                // Header bar: ← Back + centered title
                ZStack {
                    Text(item.name)
                        .font(.ui(14, weight: .bold))
                        .foregroundColor(theme.text)
                        .lineLimit(1)
                        .padding(.horizontal, 90)
                    HStack {
                        backButton { vault.cancelEditing() }
                        Spacer()
                    }
                }
                .padding(.horizontal, 12)
                .padding(.top, 16)
                .padding(.bottom, 11)
                .overlay(alignment: .bottom) {
                    Rectangle().fill(theme.cardBorder).frame(height: 1)
                }

                // Form
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        // Health status banner (logins with security issues)
                        healthBanner(for: item, editing: true)

                        // Name
                        FormLabel("NAME")
                        FormTextField(placeholder: "Item name\u{2026}", text: $vault.editName)

                        // Type-specific fields
                        switch item.type {
                        case .login:
                            loginEditFields
                        case .card:
                            cardEditFields
                        case .note:
                            noteEditFields
                        }

                        // Category picker
                        if !vault.categories.isEmpty {
                            VStack(alignment: .leading, spacing: 5) {
                                FormLabel("CATEGORY")
                                ScrollView(.horizontal, showsIndicators: false) {
                                    HStack(spacing: 4) {
                                        ForEach(vault.categories) { cat in
                                            Button(action: { vault.editCategory = cat.key }) {
                                                HStack(spacing: 5) {
                                                    Circle()
                                                        .fill(Color(hex: cat.color))
                                                        .frame(width: 8, height: 8)
                                                    Text(cat.label)
                                                        .font(.ui(12))
                                                        .foregroundColor(vault.editCategory == cat.key ? theme.accentBlueLt : theme.textMuted)
                                                }
                                                .padding(.horizontal, 14)
                                                .padding(.vertical, 6)
                                                .background(vault.editCategory == cat.key ? theme.pillBg : Color.clear)
                                                .cornerRadius(20)
                                                .overlay(
                                                    RoundedRectangle(cornerRadius: 20)
                                                        .stroke(
                                                            vault.editCategory == cat.key ? theme.accentBlue.opacity(0.27) : theme.inputBorder,
                                                            lineWidth: 1
                                                        )
                                                )
                                            }
                                            .buttonStyle(.hand)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)
                }

                // Footer: Delete · Cancel · Save
                HStack(spacing: 8) {
                    Button(action: {
                        if settings.confirmBeforeDelete {
                            showDeleteConfirmation = true
                        } else {
                            vault.deleteItem(item.id)
                            vault.isEditingItem = false
                        }
                    }) {
                        Text("Delete")
                            .font(.ui(12, weight: .semibold))
                            .foregroundColor(theme.accentRed)
                    }
                    .buttonStyle(.hand)

                    Spacer()

                    Button(action: { vault.cancelEditing() }) {
                        Text("Cancel")
                            .font(.ui(12))
                            .foregroundColor(theme.textSecondary)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                            .background(theme.fieldBg)
                            .cornerRadius(8)
                    }
                    .buttonStyle(.hand)

                    Button(action: { vault.saveEditedItem() }) {
                        Text("Save")
                            .font(.ui(12, weight: .semibold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 20)
                            .padding(.vertical, 8)
                            .background(theme.accentBlue)
                            .cornerRadius(8)
                    }
                    .buttonStyle(.hand)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 11)
                .overlay(alignment: .top) {
                    Rectangle().fill(theme.cardBorder).frame(height: 1)
                }
            }
            .alert("Delete Item", isPresented: $showDeleteConfirmation) {
                Button("Delete", role: .destructive) {
                    vault.deleteItem(item.id)
                    vault.isEditingItem = false
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Are you sure you want to delete \"\(item.name)\"?")
            }
        }
    }

    // MARK: - Health Status Banner

    /// Plain-language list of an item's security issues (logins only).
    private func healthReasons(for item: VaultItem) -> [String] {
        guard item.type == .login else { return [] }
        var reasons: [String] = []
        if vault.compromisedItemIDs.contains(item.id) { reasons.append("found in a data breach") }
        if vault.weakPasswordItemIDs.contains(item.id) { reasons.append("weak") }
        if vault.reusedPasswordItemIDs.contains(item.id) { reasons.append("reused") }
        if vault.duplicateLoginItemIDs.contains(item.id) { reasons.append("duplicate login") }
        if item.passwordAge == .old {
            reasons.append("unchanged 6+ months")
        } else if item.passwordAge == .aging {
            reasons.append("unchanged 3+ months")
        }
        return reasons
    }

    /// A `.nudge`-style banner summarizing an item's security issues. Logins only —
    /// cards/notes have no health signals. When `editing` is true the action button
    /// generates a strong password into the field; otherwise it opens the edit form.
    @ViewBuilder
    private func healthBanner(for item: VaultItem, editing: Bool) -> some View {
        let reasons = healthReasons(for: item)
        if !reasons.isEmpty {
            let breached = vault.compromisedItemIDs.contains(item.id)
            let accent = breached ? theme.accentRed : theme.accentYellow
            let title = breached ? "Password compromised" : "Password needs attention"
            let canGenerate = breached
                || vault.weakPasswordItemIDs.contains(item.id)
                || vault.reusedPasswordItemIDs.contains(item.id)
                || item.passwordAge == .old
                || item.passwordAge == .aging

            HStack(alignment: .center, spacing: 9) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: 14))
                    .foregroundColor(accent)

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.ui(12, weight: .bold))
                        .foregroundColor(theme.text)
                    Text("\u{00B7} " + reasons.joined(separator: ", "))
                        .font(.ui(11))
                        .foregroundColor(theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer(minLength: 8)

                if editing {
                    if canGenerate {
                        Button(action: {
                            vault.editPassword = GeneratorViewModel.secureRandomPassword()
                            vault.showEditPassword = true
                        }) {
                            Text("Generate")
                                .font(.ui(12, weight: .bold))
                                .foregroundColor(accent)
                        }
                        .buttonStyle(.hand)
                        .help("Generate a strong password")
                    }
                } else {
                    Button(action: { vault.requestEditWithReauth(item) }) {
                        Text("Fix")
                            .font(.ui(12, weight: .bold))
                            .foregroundColor(accent)
                    }
                    .buttonStyle(.hand)
                    .help("Edit this login")
                }
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 9)
            .background(accent.opacity(0.13))
            .cornerRadius(10)
        }
    }

    // MARK: - Login Edit Fields

    @ViewBuilder
    private var loginEditFields: some View {
        FormLabel("URL")
        FormTextField(placeholder: "https://\u{2026}", text: $vault.editUrl)
        FormLabel("USERNAME")
        FormTextField(placeholder: "Username\u{2026}", text: $vault.editUsername)
        FormLabel("PASSWORD")
        HStack(spacing: 6) {
            ZStack(alignment: .trailing) {
                if vault.showEditPassword {
                    FormTextField(placeholder: "Enter or generate\u{2026}", text: $vault.editPassword)
                } else {
                    ZStack(alignment: .leading) {
                        if vault.editPassword.isEmpty {
                            Text("Enter or generate\u{2026}")
                                .font(.ui(13))
                                .foregroundColor(theme.textSecondary)
                                .padding(10)
                        }
                        SecureField("", text: $vault.editPassword)
                            .textFieldStyle(.plain)
                            .font(.ui(13))
                            .foregroundColor(theme.text)
                            .padding(10)
                    }
                    .background(theme.inputBg)
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(theme.inputBorder, lineWidth: 1)
                    )
                }
                Button(action: { vault.showEditPassword.toggle() }) {
                    Text(vault.showEditPassword ? "Hide" : "Show")
                        .font(.ui(11))
                        .foregroundColor(theme.textFaint)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 4)
                }
                .buttonStyle(.hand)
                .padding(.trailing, 6)
            }

            Button(action: {
                vault.editPassword = GeneratorViewModel.secureRandomPassword()
            }) {
                Text("\u{26A1} Gen")
                    .font(.ui(12, weight: .semibold))
                    .foregroundColor(theme.accentPurple)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(theme.accentPurple.opacity(0.08))
                    .cornerRadius(8)
            }
            .buttonStyle(.hand)
        }
        FormLabel("2FA SECRET (OPTIONAL)")
        FormTextField(placeholder: "Paste base32 key or otpauth:// URI", text: $vault.editTotpSecret)
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                FormLabel("NOTES (OPTIONAL)")
                Spacer()
                NoteExpandButton {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        vault.showExpandedNote = true
                    }
                }
            }
            PlainTextEditor(text: $vault.editLoginNotes, textColor: NSColor(theme.text), insertionPointColor: NSColor(theme.text))
                .padding(6)
                .frame(minHeight: 50)
                .background(theme.inputBg)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(theme.inputBorder, lineWidth: 1)
                )
        }
        .onAppear {
            if settings.alwaysExpandNotes && !vault.expandedNoteAutoOpened && !vault.editLoginNotes.isEmpty {
                vault.expandedNoteAutoOpened = true
                vault.showExpandedNote = true
            }
        }
    }

    // MARK: - Card Edit Fields

    @ViewBuilder
    private var cardEditFields: some View {
        HStack {
            Text("Card Type")
                .font(.ui(13))
                .foregroundColor(theme.text)
            Spacer()
            FlapsyDropdown(
                value: vault.editCardType.isEmpty ? "Select type" : vault.editCardType,
                options: VaultItem.cardTypes,
                onChange: { vault.editCardType = $0 },
                width: 190
            )
        }
        .padding(.vertical, 4)
        .zIndex(10)
        FormLabel("CARDHOLDER")
        FormTextField(placeholder: "Name on card\u{2026}", text: $vault.editCardHolder)
        FormLabel("CARD NUMBER")
        FormTextField(placeholder: "0000 0000 0000 0000", text: $vault.editCardNumber)
            .onChange(of: vault.editCardNumber) { val in
                let formatted = VaultViewModel.formatCardNumber(val)
                if formatted != val { vault.editCardNumber = formatted }
            }
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                FormLabel("EXPIRY")
                FormTextField(placeholder: "MM/YY", text: $vault.editExpiry)
                    .onChange(of: vault.editExpiry) { val in
                        let formatted = VaultViewModel.formatExpiry(val)
                        if formatted != val { vault.editExpiry = formatted }
                    }
            }
            VStack(alignment: .leading, spacing: 4) {
                FormLabel("CVV")
                FormTextField(placeholder: "\u{2022}\u{2022}\u{2022}", text: $vault.editCvv)
                    .onChange(of: vault.editCvv) { val in
                        let formatted = VaultViewModel.formatCVV(val)
                        if formatted != val { vault.editCvv = formatted }
                    }
            }
        }
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                FormLabel("NOTES (OPTIONAL)")
                Spacer()
                NoteExpandButton {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        vault.showExpandedNote = true
                    }
                }
            }
            PlainTextEditor(text: $vault.editCardNotes, textColor: NSColor(theme.text), insertionPointColor: NSColor(theme.text))
                .padding(6)
                .frame(minHeight: 50)
                .background(theme.inputBg)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(theme.inputBorder, lineWidth: 1)
                )
        }
        .onAppear {
            if settings.alwaysExpandNotes && !vault.expandedNoteAutoOpened && !vault.editCardNotes.isEmpty {
                vault.expandedNoteAutoOpened = true
                vault.showExpandedNote = true
            }
        }
    }

    // MARK: - Note Edit Fields

    @ViewBuilder
    private var noteEditFields: some View {
        HStack {
            FormLabel("SECURE NOTE")
            Spacer()
            NoteExpandButton {
                withAnimation(.easeInOut(duration: 0.15)) {
                    vault.showExpandedNote = true
                }
            }
        }
        PlainTextEditor(text: $vault.editNoteText, textColor: NSColor(theme.text), insertionPointColor: NSColor(theme.text))
            .padding(6)
            .frame(minHeight: 80)
            .background(theme.inputBg)
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(theme.inputBorder, lineWidth: 1)
            )
            .onAppear {
                if settings.alwaysExpandNotes && !vault.expandedNoteAutoOpened && !vault.editNoteText.isEmpty {
                    vault.expandedNoteAutoOpened = true
                    vault.showExpandedNote = true
                }
            }
    }

    // MARK: - Type Icon

    // MARK: - Login Detail

    @ViewBuilder
    private func loginDetail(_ item: VaultItem) -> some View {
        if let url = item.url, !url.isEmpty {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("URL")
                        .font(.ui(9))
                        .foregroundColor(theme.textFaint)
                        .tracking(1)
                    Text(url)
                        .font(.ui(13))
                        .foregroundColor(theme.accentBlueLt)
                        .onHover { hovering in
                            if hovering {
                                NSCursor.pointingHand.push()
                            } else {
                                NSCursor.pop()
                            }
                        }
                        .onTapGesture {
                            let urlString = url.hasPrefix("http://") || url.hasPrefix("https://") ? url : "https://\(url)"
                            if let openURL = URL(string: urlString) {
                                NSWorkspace.shared.open(openURL)
                            }
                        }
                }
                Spacer()
                HStack(spacing: 4) {
                    if settings.openURLCopyPassword,
                       let password = item.password, !password.isEmpty {
                        IconButton(
                            icon: vault.copiedField == "pass" ? "checkmark" : "arrow.up.forward.app",
                            isActive: vault.copiedField == "pass",
                            action: {
                                vault.copyToClipboard(password, fieldName: "pass")
                                let urlString = url.hasPrefix("http://") || url.hasPrefix("https://") ? url : "https://\(url)"
                                if let openURL = URL(string: urlString) {
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                                        NSWorkspace.shared.open(openURL)
                                    }
                                }
                            }
                        )
                    }
                    IconButton(
                        icon: vault.copiedField == "url" ? "checkmark" : "doc.on.doc",
                        isActive: vault.copiedField == "url",
                        action: { vault.copyToClipboard(url, fieldName: "url") }
                    )
                }
            }
            .padding(12)
            .background(theme.fieldBg)
            .cornerRadius(8)
        }

        if let username = item.username {
            DetailFieldRow(
                label: "USERNAME",
                value: username,
                copyAction: { vault.copyToClipboard(username, fieldName: "user") },
                isCopied: vault.copiedField == "user"
            )
        }

        if let password = item.password {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("PASSWORD")
                        .font(.ui(9))
                        .foregroundColor(theme.textFaint)
                        .tracking(1)
                    Text(vault.showPassword ? password : String(repeating: "\u{2022}", count: 14))
                        .font(.mono(13))
                        .foregroundColor(vault.showPassword ? theme.text : theme.accentBlueLt)
                }
                Spacer()
                HStack(spacing: 4) {
                    IconButton(
                        icon: vault.showPassword ? "eye.slash" : "eye",
                        isActive: false,
                        action: { vault.showPassword.toggle() }
                    )
                    IconButton(
                        icon: vault.copiedField == "pass" ? "checkmark" : "doc.on.doc",
                        isActive: vault.copiedField == "pass",
                        action: { vault.copyToClipboard(password, fieldName: "pass") }
                    )
                }
            }
            .padding(12)
            .background(theme.fieldBg)
            .cornerRadius(8)

        if let totp = item.totpSecret, !totp.isEmpty {
            TOTPDisplayRow(secret: totp)
        }

            // Strength bar
            let strength = PasswordStrength.calculate(password)
            HStack(spacing: 10) {
                Text("STRENGTH")
                    .font(.ui(9))
                    .foregroundColor(theme.textFaint)
                    .tracking(1)
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 2)
                            .fill(theme.fieldBg)
                        RoundedRectangle(cornerRadius: 2)
                            .fill(PasswordStrength.color(for: strength))
                            .frame(width: geo.size.width * CGFloat(strength) / 100)
                    }
                }
                .frame(height: 4)
                Text("\(strength)%")
                    .font(.ui(11, weight: .semibold))
                    .foregroundColor(PasswordStrength.color(for: strength))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 4)

            // Password age
            if let age = item.passwordAge, age != .fresh, let days = item.passwordAgeDays {
                let ageColor = age == .old ? theme.accentRed : theme.accentYellow
                let ageLabel: String = {
                    if days >= 365 {
                        let years = days / 365
                        return "\(years) year\(years == 1 ? "" : "s") old"
                    }
                    let months = days / 30
                    return "\(months) month\(months == 1 ? "" : "s") old"
                }()
                HStack(spacing: 6) {
                    Image(systemName: "clock.badge.exclamationmark")
                        .font(.system(size: 11))
                        .foregroundColor(ageColor)
                    Text("Password is \(ageLabel) — consider rotating it")
                        .font(.ui(10))
                        .foregroundColor(ageColor)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(ageColor.opacity(0.08))
                .cornerRadius(6)
            }

            // Password history
            if let history = item.previousPasswords, !history.isEmpty {
                PasswordHistorySection(history: history)
            }
        }

        if let notes = item.loginNotes, !notes.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text("NOTES")
                        .font(.ui(9))
                        .foregroundColor(theme.textFaint)
                        .tracking(1)
                    Spacer()
                    NoteExpandButton {
                        withAnimation(.easeInOut(duration: 0.15)) {
                            vault.showExpandedNote = true
                        }
                    }
                }
                Text(notes)
                    .font(.ui(12))
                    .foregroundColor(theme.textSecondary)
                    .lineSpacing(3)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(theme.fieldBg)
            .cornerRadius(8)
        }
    }

    // MARK: - Card Detail

    @ViewBuilder
    private func cardDetail(_ item: VaultItem) -> some View {
        if let cardType = item.cardType, !cardType.isEmpty {
            HStack(spacing: 6) {
                Text(cardType)
                    .font(.ui(11, weight: .medium))
                    .foregroundColor(theme.accentBlueLt)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(theme.accentBlue.opacity(0.1))
                    .cornerRadius(6)
                Spacer()
            }
        }

        if let holder = item.cardHolder {
            DetailFieldRow(
                label: "CARDHOLDER",
                value: holder,
                copyAction: { vault.copyToClipboard(holder, fieldName: "holder") },
                isCopied: vault.copiedField == "holder"
            )
        }

        if let number = item.cardNumber {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("CARD NUMBER")
                        .font(.ui(9))
                        .foregroundColor(theme.textFaint)
                        .tracking(1)
                    Text(vault.showCardNumber ? number : "\u{2022}\u{2022}\u{2022}\u{2022} \u{2022}\u{2022}\u{2022}\u{2022} \u{2022}\u{2022}\u{2022}\u{2022} \(String(number.suffix(4)))")
                        .font(.ui(13))
                        .foregroundColor(vault.showCardNumber ? theme.text : theme.accentBlueLt)
                        .tracking(1)
                }
                Spacer()
                HStack(spacing: 4) {
                    IconButton(
                        icon: vault.showCardNumber ? "eye.slash" : "eye",
                        isActive: false,
                        action: { vault.showCardNumber.toggle() }
                    )
                    IconButton(
                        icon: vault.copiedField == "cardnum" ? "checkmark" : "doc.on.doc",
                        isActive: vault.copiedField == "cardnum",
                        action: { vault.copyToClipboard(number, fieldName: "cardnum") }
                    )
                }
            }
            .padding(12)
            .background(theme.fieldBg)
            .cornerRadius(8)
        }

        HStack(spacing: 6) {
            if let expiry = item.expiry {
                DetailFieldRow(
                    label: "EXPIRY",
                    value: expiry,
                    copyAction: { vault.copyToClipboard(expiry, fieldName: "exp") },
                    isCopied: vault.copiedField == "exp"
                )
            }
            if let cvv = item.cvv {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("CVV")
                            .font(.ui(9))
                            .foregroundColor(theme.textFaint)
                            .tracking(1)
                        Text(vault.showCVV ? cvv : "\u{2022}\u{2022}\u{2022}")
                            .font(.ui(13))
                            .foregroundColor(vault.showCVV ? theme.text : theme.accentBlueLt)
                    }
                    Spacer()
                    HStack(spacing: 4) {
                        IconButton(
                            icon: vault.showCVV ? "eye.slash" : "eye",
                            isActive: false,
                            action: { vault.showCVV.toggle() }
                        )
                        IconButton(
                            icon: vault.copiedField == "cvv" ? "checkmark" : "doc.on.doc",
                            isActive: vault.copiedField == "cvv",
                            action: { vault.copyToClipboard(cvv, fieldName: "cvv") }
                        )
                    }
                }
                .padding(12)
                .background(theme.fieldBg)
                .cornerRadius(8)
            }
        }

        if let notes = item.cardNotes, !notes.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text("NOTES")
                        .font(.ui(9))
                        .foregroundColor(theme.textFaint)
                        .tracking(1)
                    Spacer()
                    NoteExpandButton {
                        withAnimation(.easeInOut(duration: 0.15)) {
                            vault.showExpandedNote = true
                        }
                    }
                }
                Text(notes)
                    .font(.ui(12))
                    .foregroundColor(theme.textSecondary)
                    .lineSpacing(3)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(theme.fieldBg)
            .cornerRadius(8)
        }
    }

    // MARK: - Note Detail

    @ViewBuilder
    private func noteDetail(_ item: VaultItem) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("SECURE NOTE")
                    .font(.ui(9))
                    .foregroundColor(theme.textFaint)
                    .tracking(1)
                Spacer()
                NoteExpandButton {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        vault.showExpandedNote = true
                    }
                }
                Button(action: { showMarkdownPreview.toggle() }) {
                    HStack(spacing: 4) {
                        Image(systemName: showMarkdownPreview ? "doc.richtext" : "doc.plaintext")
                            .font(.system(size: 10))
                        Text(showMarkdownPreview ? "Rich" : "Raw")
                            .font(.ui(10))
                    }
                    .foregroundColor(theme.textFaint)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 3)
                    .background(theme.fieldBg)
                    .cornerRadius(4)
                }
                .buttonStyle(.hand)
            }

            if showMarkdownPreview {
                MarkdownTextView(text: item.noteText ?? "", theme: theme, highlightText: vault.searchText)
            } else {
                SelectableText(text: item.noteText ?? "", theme: theme, highlightText: vault.searchText)
            }

            HStack {
                Spacer()
                IconButton(
                    icon: vault.copiedField == "note" ? "checkmark" : "doc.on.doc",
                    isActive: vault.copiedField == "note",
                    action: { vault.copyToClipboard(item.noteText ?? "", fieldName: "note") }
                )
            }
        }
        .padding(12)
        .background(theme.fieldBg)
        .cornerRadius(8)
    }
}

// MARK: - Re-authentication Overlay

struct ReauthOverlay: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    var body: some View {
        ZStack {
            Color.black.opacity(0.85)
                .ignoresSafeArea()

            VStack(spacing: 12) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 20))
                    .foregroundColor(theme.accentBlueLt)

                Text("Re-authenticate")
                    .font(.ui(13, weight: .bold))
                    .foregroundColor(theme.text)

                Text("Enter your master password to edit credentials")
                    .font(.ui(10))
                    .foregroundColor(theme.textSecondary)
                    .multilineTextAlignment(.center)

                ZStack(alignment: .leading) {
                    if vault.reauthPassword.isEmpty {
                        Text("Master password")
                            .font(.ui(13))
                            .foregroundColor(theme.textMuted)
                            .padding(10)
                    }
                    SecureField("", text: $vault.reauthPassword)
                        .textFieldStyle(.plain)
                        .font(.ui(13))
                        .foregroundColor(theme.text)
                        .padding(10)
                }
                .background(theme.inputBg)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(vault.reauthError.isEmpty ? theme.inputBorder : theme.accentRed, lineWidth: 1)
                )

                if !vault.reauthError.isEmpty {
                    Text(vault.reauthError)
                        .font(.ui(10))
                        .foregroundColor(theme.accentRed)
                }

                HStack(spacing: 8) {
                    Button(action: { vault.confirmReauth() }) {
                        HStack(spacing: 4) {
                            if vault.isReauthenticating {
                                ProgressView()
                                    .controlSize(.small)
                                    .tint(.white)
                            }
                            Text(vault.isReauthenticating ? "Verifying..." : "Confirm")
                                .font(.ui(12, weight: .semibold))
                        }
                        .foregroundColor(.white)
                        .padding(.horizontal, 16)
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
                    .keyboardShortcut(.defaultAction)
                    .disabled(vault.isReauthenticating)

                    Button(action: { vault.cancelReauth() }) {
                        Text("Cancel")
                            .font(.ui(12))
                            .foregroundColor(theme.textSecondary)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                            .background(theme.fieldBg)
                            .cornerRadius(8)
                    }
                    .buttonStyle(.hand)
                    .keyboardShortcut(.cancelAction)
                }
            }
            .padding(20)
            .frame(maxWidth: 300)
            .background(theme.dropBg)
            .background(theme.cardBg)
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(theme.cardBorder, lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.3), radius: 20)
        }
    }
}

// MARK: - Password History Section

struct PasswordHistorySection: View {
    let history: [PasswordHistoryEntry]
    @Environment(\.theme) var theme
    @EnvironmentObject var vault: VaultViewModel
    @State private var expanded = false
    @State private var revealedID: UUID? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button(action: { withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() } }) {
                HStack(spacing: 6) {
                    Image(systemName: expanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 8))
                    Text("PASSWORD HISTORY")
                        .font(.ui(9))
                        .tracking(1)
                    Text("(\(history.count))")
                        .font(.ui(9))
                }
                .foregroundColor(theme.textFaint)
            }
            .buttonStyle(.hand)

            if expanded {
                VStack(spacing: 4) {
                    ForEach(history) { entry in
                        HStack(spacing: 8) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(revealedID == entry.id ? entry.password : String(repeating: "\u{2022}", count: 14))
                                    .font(.mono(11))
                                    .foregroundColor(revealedID == entry.id ? theme.text : theme.textSecondary)
                                    .lineLimit(1)
                                Text(entry.changedAt.formatted(.dateTime.month(.abbreviated).day().year().hour().minute()))
                                    .font(.ui(9))
                                    .foregroundColor(theme.textGhost)
                            }
                            Spacer()
                            HStack(spacing: 4) {
                                IconButton(
                                    icon: revealedID == entry.id ? "eye.slash" : "eye",
                                    isActive: false,
                                    action: { revealedID = revealedID == entry.id ? nil : entry.id }
                                )
                                IconButton(
                                    icon: vault.copiedField == "hist-\(entry.id)" ? "checkmark" : "doc.on.doc",
                                    isActive: vault.copiedField == "hist-\(entry.id)",
                                    action: { vault.copyToClipboard(entry.password, fieldName: "hist-\(entry.id)") }
                                )
                            }
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(theme.fieldBg)
                        .cornerRadius(6)
                    }
                }
            }
        }
        .padding(12)
        .background(theme.cardBg)
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(theme.cardBorder, lineWidth: 1)
        )
    }
}

// MARK: - Markdown Text View

struct MarkdownTextView: View {
    let text: String
    let theme: FlapsyTheme
    var highlightText: String = ""

    var body: some View {
        if var attributed = try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)) {
            let _ = Self.applyHighlight(to: &attributed, query: highlightText, theme: theme)
            Text(attributed)
                .font(.ui(12))
                .foregroundColor(theme.text)
                .textSelection(.enabled)
                .lineSpacing(4)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            SelectableText(text: text, theme: theme, highlightText: highlightText)
        }
    }

    private static func applyHighlight(to attributed: inout AttributedString, query: String, theme: FlapsyTheme) {
        guard !query.isEmpty else { return }
        let plain = String(attributed.characters).lowercased()
        let queryLower = query.lowercased()
        var searchStart = plain.startIndex
        while let range = plain.range(of: queryLower, range: searchStart..<plain.endIndex) {
            let attrStart = attributed.index(attributed.startIndex, offsetByCharacters: plain.distance(from: plain.startIndex, to: range.lowerBound))
            let attrEnd = attributed.index(attrStart, offsetByCharacters: plain.distance(from: range.lowerBound, to: range.upperBound))
            attributed[attrStart..<attrEnd].backgroundColor = theme.accentGreen.opacity(0.5)
            attributed[attrStart..<attrEnd].foregroundColor = theme.text
            searchStart = range.upperBound
        }
    }
}

// MARK: - Detail Field Row

struct DetailFieldRow: View {
    let label: String
    let value: String
    var valueColor: Color? = nil
    let copyAction: () -> Void
    let isCopied: Bool

    @Environment(\.theme) var theme

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.ui(9))
                    .foregroundColor(theme.textFaint)
                    .tracking(1)
                Text(value)
                    .font(.mono(13))
                    .foregroundColor(valueColor ?? theme.text)
            }
            Spacer()
            IconButton(
                icon: isCopied ? "checkmark" : "doc.on.doc",
                isActive: isCopied,
                action: copyAction
            )
        }
        .padding(12)
        .background(theme.fieldBg)
        .cornerRadius(8)
    }
}

// MARK: - Icon Button

struct IconButton: View {
    let icon: String
    let isActive: Bool
    let action: () -> Void

    @Environment(\.theme) var theme

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(isActive ? theme.accentGreen : theme.textSecondary)
                .frame(width: 28, height: 28)
                .background(isActive ? theme.accentGreen.opacity(0.2) : theme.fieldBg)
                .cornerRadius(6)
        }
        .buttonStyle(.hand)
    }
}

// MARK: - Selectable Text (read-only, supports text selection + Cmd+C)

struct SelectableText: View {
    let text: String
    let theme: FlapsyTheme
    var highlightText: String = ""

    var body: some View {
        SelectableTextRepresentable(text: text, theme: theme, highlightText: highlightText)
            .frame(height: Self.calculateHeight(text: text))
    }

    static func calculateHeight(text: String) -> CGFloat {
        let font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        let style = NSMutableParagraphStyle()
        style.lineSpacing = 4
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .paragraphStyle: style]
        let rect = (text as NSString).boundingRect(
            with: NSSize(width: 280, height: CGFloat.greatestFiniteMagnitude),
            options: [.usesLineFragmentOrigin, .usesFontLeading],
            attributes: attrs
        )
        return max(ceil(rect.height) + 4, 20)
    }
}

private struct SelectableTextRepresentable: NSViewRepresentable {
    let text: String
    let theme: FlapsyTheme
    var highlightText: String = ""

    func makeNSView(context: Context) -> NSTextView {
        let textView = NSTextView()
        textView.isEditable = false
        textView.isSelectable = true
        textView.drawsBackground = false
        textView.textContainerInset = .zero
        textView.textContainer?.lineFragmentPadding = 0
        textView.textContainer?.widthTracksTextView = true
        textView.isVerticallyResizable = false
        textView.isHorizontallyResizable = false
        textView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.textColor = NSColor(theme.text)
        applyText(textView)
        return textView
    }

    func updateNSView(_ textView: NSTextView, context: Context) {
        applyText(textView)
        textView.textColor = NSColor(theme.text)
    }

    private func applyText(_ textView: NSTextView) {
        if textView.string != text {
            textView.string = text
        }
        let style = NSMutableParagraphStyle()
        style.lineSpacing = 4
        textView.defaultParagraphStyle = style
        if let storage = textView.textStorage {
            let range = NSRange(location: 0, length: storage.length)
            storage.addAttribute(.paragraphStyle, value: style, range: range)
            // Remove old highlights
            storage.removeAttribute(.backgroundColor, range: range)
            // Apply search highlights
            if !highlightText.isEmpty {
                let nsText = (text as NSString).lowercased as NSString
                let query = (highlightText as NSString).lowercased as NSString
                var searchRange = NSRange(location: 0, length: nsText.length)
                let highlightColor = NSColor(red: 0.2, green: 0.83, blue: 0.6, alpha: 0.5)
                while searchRange.location < nsText.length {
                    let found = nsText.range(of: query as String, options: [], range: searchRange)
                    guard found.location != NSNotFound else { break }
                    storage.addAttribute(.backgroundColor, value: highlightColor, range: found)
                    searchRange.location = found.location + found.length
                    searchRange.length = nsText.length - searchRange.location
                }
            }
        }
    }
}

// MARK: - TOTP Display Row

struct TOTPDisplayRow: View {
    let secret: String
    @Environment(\.theme) var theme
    @EnvironmentObject var vault: VaultViewModel
    @State private var code: String = "------"
    @State private var remaining: Int = 30
    @State private var timer: Timer?

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("2FA CODE")
                    .font(.ui(9))
                    .foregroundColor(theme.textFaint)
                    .tracking(1)
                HStack(spacing: 8) {
                    Text(formatCode(code))
                        .font(.mono(18, weight: .semibold))
                        .foregroundColor(theme.accentBlueLt)
                    HStack(spacing: 3) {
                        TOTPCountdownArc(remaining: remaining, period: 30)
                            .frame(width: 16, height: 16)
                        Text("\(remaining)s")
                            .font(.ui(10, weight: .medium))
                            .foregroundColor(remaining <= 5 ? theme.accentRed : theme.textSecondary)
                    }
                }
            }
            Spacer()
            IconButton(
                icon: vault.copiedField == "totp" ? "checkmark" : "doc.on.doc",
                isActive: vault.copiedField == "totp",
                action: { vault.copyToClipboard(code, fieldName: "totp") }
            )
        }
        .padding(12)
        .background(theme.fieldBg)
        .cornerRadius(8)
        .onAppear { startTimer() }
        .onDisappear { stopTimer() }
    }

    private func formatCode(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return String(code.prefix(3)) + " " + String(code.suffix(3))
    }

    private func refreshCode() {
        if let result = TOTPService.generate(secret: secret) {
            code = result.code
            remaining = result.remaining
        }
    }

    private func startTimer() {
        refreshCode()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            refreshCode()
        }
    }

    private func stopTimer() {
        timer?.invalidate()
        timer = nil
    }
}

// MARK: - TOTP Countdown Arc

struct TOTPCountdownArc: View {
    let remaining: Int
    let period: Int
    @Environment(\.theme) var theme

    var body: some View {
        ZStack {
            Circle()
                .stroke(theme.fieldBg, lineWidth: 2)
            Circle()
                .trim(from: 0, to: CGFloat(remaining) / CGFloat(period))
                .stroke(
                    remaining <= 5 ? theme.accentRed : theme.accentBlue,
                    style: StrokeStyle(lineWidth: 2, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: remaining)
        }
    }
}
