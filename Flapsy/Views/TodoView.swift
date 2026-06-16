import SwiftUI

/// The To-Do mini-app: a single-panel personal task list opened from the ⋯ menu.
/// Tasks persist encrypted alongside the vault. Renders below the shared back bar.
struct TodoView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @FocusState private var addFocused: Bool
    @State private var datePickerTask: UUID? = nil
    @State private var pickedDate = Date()

    var body: some View {
        VStack(spacing: 0) {
            progressHeader
            addField
            filterRow

            Divider().overlay(theme.cardBorder)

            if vault.filteredTasks.isEmpty {
                emptyState
            } else if vault.todoIsAgenda {
                agendaList
            } else {
                flatList
            }
        }
        .onAppear {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { addFocused = true }
        }
    }

    // MARK: - Header progress

    private var progressHeader: some View {
        let p = vault.todoProgress
        let fraction = p.total == 0 ? 0 : CGFloat(p.done) / CGFloat(p.total)
        return VStack(spacing: 6) {
            HStack {
                Text("\(p.done) of \(p.total) done")
                    .font(.ui(11, weight: .medium))
                    .foregroundColor(theme.textMuted)
                Spacer()
                Text("\(p.done)/\(p.total)")
                    .font(.mono(11, weight: .semibold))
                    .foregroundColor(theme.accentBlue)
            }
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule().fill(theme.fieldBg).frame(height: 4)
                    Capsule().fill(theme.accentBlue).frame(width: geo.size.width * fraction, height: 4)
                }
            }
            .frame(height: 4)
        }
        .padding(.horizontal, 16)
        .padding(.top, 10)
        .padding(.bottom, 8)
    }

    // MARK: - Quick add

    private var addField: some View {
        HStack(spacing: 10) {
            Image(systemName: "plus")
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(theme.textFaint)
            ZStack(alignment: .leading) {
                if vault.newTaskText.isEmpty {
                    Text("Add a task, then press Enter")
                        .font(.ui(13))
                        .foregroundColor(theme.textFaint)
                }
                TextField("", text: $vault.newTaskText)
                    .textFieldStyle(.plain)
                    .font(.ui(13))
                    .foregroundColor(theme.text)
                    .focused($addFocused)
                    .onSubmit { vault.addTask(vault.newTaskText) }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 11)
        .background(theme.inputBg)
        .cornerRadius(10)
        .padding(.horizontal, 16)
        .padding(.bottom, 10)
    }

    // MARK: - Filters

    private var filterRow: some View {
        HStack(spacing: 8) {
            ForEach(TaskStatusFilter.allCases, id: \.self) { status in
                statusPill(status)
            }

            Rectangle().fill(theme.cardBorder).frame(width: 1, height: 16)

            // Flag-only tab
            Button(action: { vault.todoFlagOnly.toggle() }) {
                Image(systemName: vault.todoFlagOnly ? "flag.fill" : "flag")
                    .font(.system(size: 12))
                    .foregroundColor(vault.todoFlagOnly ? theme.accentRed : theme.textMuted)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 5)
                    .background(vault.todoFlagOnly ? theme.accentRed.opacity(0.12) : Color.clear)
                    .cornerRadius(7)
            }
            .buttonStyle(.hand)

            Spacer()

            scopeMenu
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }

    private func statusPill(_ status: TaskStatusFilter) -> some View {
        let active = vault.todoStatus == status
        return Button(action: { vault.todoStatus = status }) {
            Text(status.label)
                .font(.ui(12, weight: .semibold))
                .foregroundColor(active ? theme.accentBlueLt : theme.textMuted)
                .padding(.horizontal, 12)
                .padding(.vertical, 5)
                .background(active ? theme.pillBg : Color.clear)
                .cornerRadius(20)
        }
        .buttonStyle(.hand)
    }

    private var scopeMenu: some View {
        let isOpen = vault.openHeaderMenu == .todoScope
        return Button(action: {
            withAnimation(.easeOut(duration: 0.12)) {
                vault.openHeaderMenu = isOpen ? nil : .todoScope
            }
        }) {
            HStack(spacing: 5) {
                Image(systemName: "calendar").font(.system(size: 11))
                Text(vault.todoScope.label).font(.ui(11, weight: .medium))
                Image(systemName: "chevron.down")
                    .font(.system(size: 8, weight: .semibold))
                    .rotationEffect(.degrees(isOpen ? 180 : 0))
            }
            .foregroundColor(isOpen ? theme.text : theme.textMuted)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(theme.fieldBg)
            .cornerRadius(7)
            .fixedSize()
        }
        .buttonStyle(.hand)
        // Report the chip's frame into the shared anchored-menu system (same as
        // the + / … / sort dropdowns).
        .background(
            GeometryReader { geo in
                Color.clear.preference(
                    key: HeaderMenuAnchorKey.self,
                    value: [HeaderMenuKind.todoScope: geo.frame(in: .named("vaultContainer"))]
                )
            }
        )
        // "Pick a date…" from the scope menu opens this popover.
        .popover(isPresented: $vault.showTodoScopeDatePicker) {
            datePickerPopover { vault.todoScope = .pick($0) }
        }
    }

    // MARK: - Lists

    private var flatList: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(vault.filteredTasks) { task in
                    taskRow(task)
                }
                if vault.hasVisibleCompleted {
                    clearCompletedButton
                }
            }
            .padding(.vertical, 4)
        }
    }

    private var agendaList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(vault.todoAgenda, id: \.bucket) { group in
                    HStack {
                        Text(group.bucket.title)
                            .font(.ui(10.5, weight: .bold))
                            .tracking(0.6)
                            .foregroundColor(group.bucket == .overdue ? theme.accentRed : theme.textFaint)
                        Spacer()
                        Text("\(group.tasks.count)")
                            .font(.mono(10))
                            .foregroundColor(theme.textFaint)
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 12)
                    .padding(.bottom, 4)

                    ForEach(group.tasks) { task in
                        taskRow(task)
                    }
                }

                if vault.hasVisibleCompleted {
                    clearCompletedButton
                }
            }
            .padding(.bottom, 8)
        }
    }

    private var clearCompletedButton: some View {
        Button(action: {
            withAnimation(.easeInOut(duration: 0.15)) { vault.clearCompletedTasks() }
        }) {
            Text("Clear completed")
                .font(.ui(12, weight: .semibold))
                .foregroundColor(theme.accentRed)
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
                .background(theme.fieldBg)
                .cornerRadius(8)
        }
        .buttonStyle(.hand)
        .frame(maxWidth: .infinity)
        .padding(.top, 10)
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "checklist")
                .font(.system(size: 30))
                .foregroundColor(theme.textGhost)
            Text("No tasks")
                .font(.ui(13, weight: .medium))
                .foregroundColor(theme.textFaint)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Task row

    private func taskRow(_ task: TodoTask) -> some View {
        TaskRow(
            task: task,
            onToggle: { vault.toggleTask(task.id) },
            onFlag: { vault.toggleTaskFlag(task.id) },
            onDelete: { vault.deleteTask(task.id) },
            onEdit: { vault.editTaskText(task.id, $0) },
            onPreset: { vault.setTaskDue(task.id, VaultViewModel.presetDate($0)) },
            onClearDate: { vault.setTaskDue(task.id, nil) },
            onRepeat: { vault.setTaskRepeat(task.id, $0) },
            onPickDate: { datePickerTask = task.id }
        )
        .popover(isPresented: Binding(
            get: { datePickerTask == task.id },
            set: { if !$0 { datePickerTask = nil } }
        )) {
            datePickerPopover { vault.setTaskDue(task.id, $0); datePickerTask = nil }
        }
    }

    // MARK: - Date picker popover

    private func datePickerPopover(_ apply: @escaping (Date) -> Void) -> some View {
        VStack(spacing: 12) {
            Text("Pick a date")
                .font(.ui(12, weight: .semibold))
                .foregroundColor(theme.text)
                .frame(maxWidth: .infinity, alignment: .leading)

            DatePicker("", selection: $pickedDate, displayedComponents: .date)
                .datePickerStyle(.graphical)
                .labelsHidden()
                .tint(theme.accentBlue)
                .frame(width: 256)

            Button(action: { apply(pickedDate) }) {
                Text("Set date")
                    .font(.ui(12, weight: .semibold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 9)
                    .background(theme.accentBlue)
                    .cornerRadius(9)
            }
            .buttonStyle(.hand)
        }
        .padding(16)
        .frame(width: 290)
        .background(theme.dropBg)
        .environment(\.font, .ui(13))
    }
}

// MARK: - Task Row

private struct TaskRow: View {
    let task: TodoTask
    let onToggle: () -> Void
    let onFlag: () -> Void
    let onDelete: () -> Void
    let onEdit: (String) -> Void
    let onPreset: (TaskDateScope) -> Void
    let onClearDate: () -> Void
    let onRepeat: (TaskRepeat) -> Void
    let onPickDate: () -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false
    @State private var editing = false
    @State private var draft = ""
    @State private var expanded = false
    @FocusState private var editFocused: Bool

    var body: some View {
        HStack(spacing: 11) {
            // Completion checkbox
            Button(action: onToggle) {
                ZStack {
                    Circle()
                        .strokeBorder(task.done ? theme.accentGreen : theme.textGhost, lineWidth: 1.6)
                        .frame(width: 20, height: 20)
                    if task.done {
                        Circle().fill(theme.accentGreen).frame(width: 20, height: 20)
                        Image(systemName: "checkmark")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.white)
                    }
                }
                .frame(width: 26, height: 26)
                .contentShape(Rectangle())
            }
            .buttonStyle(.hand)

            // Text (tap to edit; tap again to expand long text)
            if editing {
                TextField("", text: $draft)
                    .textFieldStyle(.plain)
                    .font(.ui(13.5, weight: .medium))
                    .foregroundColor(theme.text)
                    .focused($editFocused)
                    .onSubmit { commitEdit() }
                    .onChange(of: editFocused) { focused in if !focused { commitEdit() } }
            } else {
                Text(task.text)
                    .font(.ui(13.5, weight: expanded ? .regular : .medium))
                    .foregroundColor(task.done ? theme.textFaint : theme.text)
                    .strikethrough(task.done, color: theme.textFaint)
                    .lineLimit(expanded ? nil : 1)
                    .help(task.text)
                    .contentShape(Rectangle())
                    .onTapGesture(count: 2) { beginEdit() }
                    .onTapGesture { expanded.toggle() }
            }

            Spacer(minLength: 6)

            // Repeat badge
            if task.repeatRule != .never {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(theme.textFaint)
                    .help("Repeats \(task.repeatRule.label.lowercased())")
            }

            // Date chip / set-date menu (only when dated or hovering — keeps idle
            // rows free of a native Menu that would otherwise capture taps)
            if task.due != nil || hovering {
                dateMenu
            }

            // Flag (solid when set, faint on hover)
            if task.pri || hovering {
                Button(action: onFlag) {
                    Image(systemName: task.pri ? "flag.fill" : "flag")
                        .font(.system(size: 12))
                        .foregroundColor(task.pri ? theme.accentRed : theme.textFaint)
                }
                .buttonStyle(.hand)
            }

            // Delete (hover only)
            if hovering {
                Button(action: onDelete) {
                    Image(systemName: "xmark")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(theme.textFaint)
                }
                .buttonStyle(.hand)
                .help("Delete task")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .background(hovering ? theme.hoverBg : Color.clear)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
    }

    @ViewBuilder
    private var dateMenu: some View {
        Menu {
            Button { onPreset(.today) } label: { Label("Today", systemImage: "calendar") }
            Button { onPreset(.tomorrow) } label: { Label("Tomorrow", systemImage: "calendar") }
            Button { onPreset(.thisWeekend) } label: { Label("This weekend", systemImage: "calendar") }
            Button { onPreset(.nextWeek) } label: { Label("Next week", systemImage: "calendar") }
            Button { onPickDate() } label: { Label("Pick a date\u{2026}", systemImage: "calendar") }
            if task.due != nil {
                Button(role: .destructive) { onClearDate() } label: { Label("Clear date", systemImage: "xmark") }
            }
            Divider()
            Menu("Repeat") {
                ForEach(TaskRepeat.allCases, id: \.self) { rule in
                    Button { onRepeat(rule) } label: {
                        if task.repeatRule == rule {
                            Label(rule.label, systemImage: "checkmark")
                        } else {
                            Text(rule.label)
                        }
                    }
                }
            }
        } label: {
            if let label = task.dueLabel() {
                HStack(spacing: 4) {
                    Image(systemName: "calendar").font(.system(size: 9))
                    Text(label).font(.mono(10, weight: .medium))
                }
                .foregroundColor(task.isOverdue() ? theme.accentRed : theme.textMuted)
                .padding(.horizontal, 7)
                .padding(.vertical, 4)
                .background((task.isOverdue() ? theme.accentRed : theme.textMuted).opacity(0.1))
                .cornerRadius(6)
            } else if hovering {
                Image(systemName: "calendar")
                    .font(.system(size: 12))
                    .foregroundColor(theme.textFaint)
            }
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
    }

    private func beginEdit() {
        draft = task.text
        editing = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { editFocused = true }
    }

    private func commitEdit() {
        if editing {
            onEdit(draft)
            editing = false
        }
    }
}
