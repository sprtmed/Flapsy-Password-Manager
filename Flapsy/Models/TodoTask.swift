import Foundation

/// How a task repeats. `.never` = one-off.
enum TaskRepeat: String, Codable, CaseIterable {
    case never, daily, weekdays, weekly, monthly

    var label: String {
        switch self {
        case .never:    return "Never"
        case .daily:    return "Daily"
        case .weekdays: return "Weekdays"
        case .weekly:   return "Weekly"
        case .monthly:  return "Monthly"
        }
    }
}

/// A single to-do item in the To-Do mini-app.
///
/// Named `TodoTask` (not `Task`) to avoid clashing with Swift Concurrency's `Task`.
/// Persisted encrypted alongside the rest of the vault (in `VaultData.tasks`).
/// Array order is the manual sort order.
struct TodoTask: Codable, Identifiable {
    let id: UUID
    var text: String
    /// Completed (for non-repeating tasks). Repeating tasks never set this — they
    /// advance their `due` instead.
    var done: Bool
    /// Priority flag.
    var pri: Bool
    /// Due date (day granularity), or nil for "no date".
    var due: Date?
    var repeatRule: TaskRepeat
    var createdAt: Date
    var completedAt: Date?

    init(
        id: UUID = UUID(),
        text: String,
        done: Bool = false,
        pri: Bool = false,
        due: Date? = nil,
        repeatRule: TaskRepeat = .never,
        createdAt: Date = Date(),
        completedAt: Date? = nil
    ) {
        self.id = id
        self.text = text
        self.done = done
        self.pri = pri
        self.due = due
        self.repeatRule = repeatRule
        self.createdAt = createdAt
        self.completedAt = completedAt
    }

    // Forward-compatible decode so future fields don't break older vaults.
    enum CodingKeys: String, CodingKey {
        case id, text, done, pri, due, repeatRule, createdAt, completedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        text = try c.decode(String.self, forKey: .text)
        done = try c.decodeIfPresent(Bool.self, forKey: .done) ?? false
        pri = try c.decodeIfPresent(Bool.self, forKey: .pri) ?? false
        due = try c.decodeIfPresent(Date.self, forKey: .due)
        repeatRule = try c.decodeIfPresent(TaskRepeat.self, forKey: .repeatRule) ?? .never
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
        completedAt = try c.decodeIfPresent(Date.self, forKey: .completedAt)
    }
}

// MARK: - Filters

/// Status segmented control.
enum TaskStatusFilter: String, CaseIterable {
    case all, active, done
    var label: String { rawValue.capitalized }
}

/// Date-scope filter (a rule applied to each task's date, not an enumerated list).
enum TaskDateScope: Equatable {
    case anytime, today, tomorrow, thisWeekend, nextWeek, overdue, noDate
    case pick(Date)

    var label: String {
        switch self {
        case .anytime:     return "Anytime"
        case .today:       return "Today"
        case .tomorrow:    return "Tomorrow"
        case .thisWeekend: return "This weekend"
        case .nextWeek:    return "Next week"
        case .overdue:     return "Overdue"
        case .noDate:      return "No date"
        case .pick(let d):
            let f = DateFormatter()
            f.setLocalizedDateFormatFromTemplate("MMMd")
            return f.string(from: d)
        }
    }
}

// MARK: - Date helpers (computed against the live clock each render)

/// Agenda buckets a task falls into, in display order.
enum TaskBucket: Int, CaseIterable {
    case overdue, today, tomorrow, thisWeek, later, noDate, completed

    var title: String {
        switch self {
        case .overdue:   return "OVERDUE"
        case .today:     return "TODAY"
        case .tomorrow:  return "TOMORROW"
        case .thisWeek:  return "THIS WEEK"
        case .later:     return "LATER"
        case .noDate:    return "NO DATE"
        case .completed: return "COMPLETED"
        }
    }
}

extension TodoTask {
    /// Short label for the due date, relative to today (e.g. Overdue / Today /
    /// Tomorrow / "Fri" / "Jul 3"). Nil when there's no date.
    func dueLabel(now: Date = Date(), calendar: Calendar = .current) -> String? {
        guard let due = due else { return nil }
        let startToday = calendar.startOfDay(for: now)
        let startDue = calendar.startOfDay(for: due)
        let days = calendar.dateComponents([.day], from: startToday, to: startDue).day ?? 0
        if days < 0 { return "Overdue" }
        if days == 0 { return "Today" }
        if days == 1 { return "Tomorrow" }
        if days < 7 {
            let f = DateFormatter()
            f.dateFormat = "EEE"
            return f.string(from: due)
        }
        let f = DateFormatter()
        f.setLocalizedDateFormatFromTemplate("MMMd")
        return f.string(from: due)
    }

    /// Whether the due date is strictly before today.
    func isOverdue(now: Date = Date(), calendar: Calendar = .current) -> Bool {
        guard let due = due, !done else { return false }
        return calendar.startOfDay(for: due) < calendar.startOfDay(for: now)
    }

    /// The agenda bucket this task belongs to (ignores completed; the view places
    /// done tasks into `.completed` separately).
    func bucket(now: Date = Date(), calendar: Calendar = .current) -> TaskBucket {
        if done { return .completed }
        guard let due = due else { return .noDate }
        let startToday = calendar.startOfDay(for: now)
        let startDue = calendar.startOfDay(for: due)
        let days = calendar.dateComponents([.day], from: startToday, to: startDue).day ?? 0
        if days < 0 { return .overdue }
        if days == 0 { return .today }
        if days == 1 { return .tomorrow }
        if days < 7 { return .thisWeek }
        return .later
    }

    /// Advances `due` to the next occurrence per `repeatRule`, catching up past
    /// today if overdue. Returns the new due date (nil if not repeating).
    func nextOccurrence(now: Date = Date(), calendar: Calendar = .current) -> Date? {
        guard repeatRule != .never else { return nil }
        let startToday = calendar.startOfDay(for: now)
        var date = calendar.startOfDay(for: due ?? now)

        func step(_ from: Date) -> Date {
            switch repeatRule {
            case .daily:
                return calendar.date(byAdding: .day, value: 1, to: from) ?? from
            case .weekly:
                return calendar.date(byAdding: .day, value: 7, to: from) ?? from
            case .monthly:
                return calendar.date(byAdding: .month, value: 1, to: from) ?? from
            case .weekdays:
                var d = calendar.date(byAdding: .day, value: 1, to: from) ?? from
                while calendar.isDateInWeekend(d) {
                    d = calendar.date(byAdding: .day, value: 1, to: d) ?? d
                }
                return d
            case .never:
                return from
            }
        }

        // Always advance at least once, then catch up until strictly after today.
        date = step(date)
        var guardCount = 0
        while date <= startToday && guardCount < 1000 {
            date = step(date)
            guardCount += 1
        }
        return date
    }
}
