import SwiftUI

/// The To-Do mini-app: a single-panel personal task list opened from the ⋯ menu.
/// Tasks persist encrypted alongside the vault. Renders below the shared back bar.
struct TodoView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    @FocusState private var addFocused: Bool
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
            .foregroundColor(isOpen ? theme.accentBlue : theme.textMuted)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(theme.fieldBg)
            .cornerRadius(7)
            .overlay(
                RoundedRectangle(cornerRadius: 7)
                    .strokeBorder(theme.accentBlue, lineWidth: isOpen ? 1.5 : 0)
            )
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
            DatePickerCard(date: $pickedDate) {
                vault.todoScope = .pick($0)
                vault.showTodoScopeDatePicker = false
            }
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

                    // Suppress the date chip for groups whose header already states
                    // the date (Today / Tomorrow / Overdue). Keep it for This week
                    // (weekday) and Later (date), where it adds information.
                    let showChip = !(group.bucket == .today || group.bucket == .tomorrow || group.bucket == .overdue)
                    ForEach(group.tasks) { task in
                        taskRow(task, showDateLabel: showChip)
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

    private func taskRow(_ task: TodoTask, showDateLabel: Bool = true) -> some View {
        TaskRow(
            task: task,
            showDateLabel: showDateLabel,
            onToggle: { vault.toggleTask(task.id) },
            onFlag: { vault.toggleTaskFlag(task.id) },
            onDelete: { vault.deleteTask(task.id) },
            onEdit: { vault.editTaskText(task.id, $0) },
            onSetDate: { vault.setTaskDue(task.id, $0) },
            onRepeat: { vault.setTaskRepeat(task.id, $0) }
        )
    }
}

// MARK: - Task Row

private struct TaskRow: View {
    let task: TodoTask
    var showDateLabel: Bool = true
    let onToggle: () -> Void
    let onFlag: () -> Void
    let onDelete: () -> Void
    let onEdit: (String) -> Void
    let onSetDate: (Date?) -> Void
    let onRepeat: (TaskRepeat) -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false
    @State private var editing = false
    @State private var draft = ""
    @State private var expanded = false
    @State private var showDateMenu = false
    @State private var showDatePicker = false
    @State private var pickedDate = Date()
    @FocusState private var editFocused: Bool

    var body: some View {
        HStack(spacing: 11) {
            checkbox
            taskText
            Spacer(minLength: 6)
            trailing
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .background(hovering ? theme.hoverBg : Color.clear)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
    }

    private var checkbox: some View {
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
    }

    @ViewBuilder
    private var taskText: some View {
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
    }

    private var trailing: some View {
        HStack(spacing: 13) {
            // Repeat indicator — shown whenever the task repeats (darker), opens the
            // date/repeat card.
            if task.repeatRule != .never {
                trailingIcon("arrow.2.squarepath", size: 12, weight: .semibold, color: theme.textMuted) {
                    showDateMenu = true
                }
                .help("Repeats \(task.repeatRule.label.lowercased())")
            }

            // Date: chip when idle + dated + non-redundant; calendar icon on hover.
            if hovering {
                trailingIcon("calendar", size: 13, weight: .regular, color: theme.textGhost) { showDateMenu = true }
            } else if showDateLabel, let label = task.dueLabel() {
                dateChip(label)
            }

            // Flag: solid red when flagged; faint outline on hover.
            if task.pri {
                trailingIcon("flag.fill", size: 12, weight: .regular, color: theme.accentRed) { onFlag() }
            } else if hovering {
                trailingIcon("flag", size: 12, weight: .regular, color: theme.textGhost) { onFlag() }
            }

            // Delete — hover only.
            if hovering {
                trailingIcon("xmark", size: 11, weight: .semibold, color: theme.textGhost) { onDelete() }
                    .help("Delete task")
            }
        }
        .popover(isPresented: $showDateMenu, arrowEdge: .bottom) {
            TaskDateMenuCard(
                task: task,
                onSetDate: { onSetDate($0); showDateMenu = false },
                onRepeat: { onRepeat($0) },
                onPickDate: {
                    showDateMenu = false
                    pickedDate = task.due ?? Date()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.18) { showDatePicker = true }
                }
            )
        }
        .popover(isPresented: $showDatePicker, arrowEdge: .bottom) {
            DatePickerCard(date: $pickedDate) { onSetDate($0); showDatePicker = false }
        }
    }

    private func trailingIcon(_ name: String, size: CGFloat, weight: Font.Weight, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: name)
                .font(.system(size: size, weight: weight))
                .foregroundColor(color)
                .frame(width: 18, height: 18)
                .contentShape(Rectangle())
        }
        .buttonStyle(.hand)
    }

    private func dateChip(_ label: String) -> some View {
        let overdue = task.isOverdue()
        return Button(action: { showDateMenu = true }) {
            HStack(spacing: 4) {
                Image(systemName: "calendar").font(.system(size: 9))
                Text(label).font(.mono(10, weight: .medium))
            }
            .foregroundColor(overdue ? theme.accentRed : theme.textMuted)
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .background(overdue ? theme.accentRed.opacity(0.1) : theme.fieldBg)
            .cornerRadius(6)
        }
        .buttonStyle(.hand)
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

// MARK: - Per-task date / repeat card (matches the designer mockup)

private struct TaskDateMenuCard: View {
    let task: TodoTask
    let onSetDate: (Date?) -> Void
    let onRepeat: (TaskRepeat) -> Void
    let onPickDate: () -> Void

    @Environment(\.theme) var theme

    private static let fmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "d MMM"; return f
    }()

    private func presetDateString(_ scope: TaskDateScope) -> String {
        guard let d = VaultViewModel.presetDate(scope) else { return "" }
        return Self.fmt.string(from: d)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            presetRow("Today", .today)
            presetRow("Tomorrow", .tomorrow)
            presetRow("This weekend", .thisWeekend)
            presetRow("Next week", .nextWeek)
            TodoMenuRow(icon: "calendar", label: "Pick a date\u{2026}", action: onPickDate)

            divider
            if task.due != nil {
                TodoMenuRow(icon: "xmark", label: "Clear date", tint: theme.accentRed) { onSetDate(nil) }
                divider
            }

            Text("REPEAT")
                .font(.ui(9.5, weight: .bold)).tracking(0.7)
                .foregroundColor(theme.textFaint)
                .padding(.horizontal, 10).padding(.top, 3).padding(.bottom, 3)

            ForEach(TaskRepeat.allCases, id: \.self) { rule in
                TodoMenuRow(label: rule.label, checked: task.repeatRule == rule) { onRepeat(rule) }
            }
        }
        .padding(6)
        .frame(width: 236)
        .background(theme.dropBg)
    }

    private var divider: some View {
        Divider().overlay(theme.cardBorder).padding(.horizontal, 6).padding(.vertical, 4)
    }

    private func presetRow(_ label: String, _ scope: TaskDateScope) -> some View {
        TodoMenuRow(icon: "calendar", label: label, trailing: presetDateString(scope)) {
            onSetDate(VaultViewModel.presetDate(scope))
        }
    }
}

private struct TodoMenuRow: View {
    var icon: String? = nil
    var label: String
    var trailing: String? = nil
    var checked: Bool = false
    var tint: Color? = nil
    let action: () -> Void

    @Environment(\.theme) var theme
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                // Leading slot: indigo check (selected) > icon > empty (keeps labels aligned)
                ZStack {
                    if checked {
                        Image(systemName: "checkmark")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(theme.accentBlue)
                    } else if let icon {
                        Image(systemName: icon)
                            .font(.system(size: 11))
                            .foregroundColor(tint ?? theme.textMuted)
                    }
                }
                .frame(width: 15)

                Text(label)
                    .font(.ui(12.5, weight: checked ? .semibold : .regular))
                    .foregroundColor(tint ?? theme.text)

                Spacer(minLength: 8)

                if let trailing, !trailing.isEmpty {
                    Text(trailing)
                        .font(.mono(10.5))
                        .foregroundColor(theme.textFaint)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity)
            .background(hovering ? theme.hoverBg : Color.clear)
            .cornerRadius(7)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

// MARK: - Styled graphical date picker (shared by task rows + scope filter)

private struct DatePickerCard: View {
    @Binding var date: Date
    let onSet: (Date) -> Void
    @Environment(\.theme) var theme

    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Text("Pick a date")
                    .font(.ui(12, weight: .semibold))
                    .foregroundColor(theme.text)
                Spacer()
                Text(date.formatted(.dateTime.weekday(.abbreviated).day().month(.abbreviated)))
                    .font(.mono(11, weight: .semibold))
                    .foregroundColor(theme.accentBlue)
            }

            DatePicker("", selection: $date, displayedComponents: .date)
                .datePickerStyle(.graphical)
                .labelsHidden()
                .tint(theme.accentBlue)
                .accentColor(theme.accentBlue)
                .frame(width: 248)

            Button(action: { onSet(date) }) {
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
        .frame(width: 286)
        .background(theme.dropBg)
        .environment(\.font, .ui(13))
    }
}
