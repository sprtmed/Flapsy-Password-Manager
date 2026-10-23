import Foundation

/// Reads a due date, flag and repeat out of quick-add text:
/// "Pay rent fri !" → "Pay rent", due Friday, flagged.
///
/// Unambiguous words work anywhere ("today", "tomorrow", "friday", "next week",
/// "this weekend", "in 3 days", "12 nov", "every week"). Short forms that are also
/// ordinary words ("sun", "sat", "wed", "tmr", "weekend") only count as the last word
/// or right after "on" / "by" / "due". Only the first date is used; "!" flags the task.
struct TaskQuickAdd: Equatable {
    var title: String
    var due: Date?
    var flagged = false
    var repeatRule: TaskRepeat = .never

    /// Whether anything besides the title was recognised (drives the live preview).
    var hasExtras: Bool { due != nil || flagged || repeatRule != .never }

    private static let fullWeekdays: [String: Int] = [
        "sunday": 1, "monday": 2, "tuesday": 3, "wednesday": 4,
        "thursday": 5, "friday": 6, "saturday": 7,
    ]
    private static let shortWeekdays: [String: Int] = [
        "sun": 1, "mon": 2, "tue": 3, "tues": 3, "wed": 4,
        "thu": 5, "thur": 5, "thurs": 5, "fri": 6, "sat": 7,
    ]
    private static let months: [String: Int] = [
        "jan": 1, "january": 1, "feb": 2, "february": 2, "mar": 3, "march": 3,
        "apr": 4, "april": 4, "may": 5, "jun": 6, "june": 6, "jul": 7, "july": 7,
        "aug": 8, "august": 8, "sep": 9, "sept": 9, "september": 9,
        "oct": 10, "october": 10, "nov": 11, "november": 11, "dec": 12, "december": 12,
    ]
    /// Words that may introduce a date ("Pay rent on fri") and are dropped with it.
    private static let datePrepositions: Set<String> = ["on", "by", "due"]

    static func parse(_ text: String, now: Date = Date(), calendar: Calendar = .current) -> TaskQuickAdd {
        let words = text.split(separator: " ").map(String.init)
        let norm = words.map { $0.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".,;:")) }
        let today = calendar.startOfDay(for: now)
        var removed = Set<Int>()
        var result = TaskQuickAdd(title: text.trimmingCharacters(in: .whitespaces))

        func word(_ i: Int) -> String? { i >= 0 && i < norm.count && !removed.contains(i) ? norm[i] : nil }
        func addDays(_ n: Int) -> Date { calendar.date(byAdding: .day, value: n, to: today) ?? today }
        /// The coming `weekday`, or today if it's that day already.
        func upcoming(_ weekday: Int) -> Date {
            calendar.component(.weekday, from: today) == weekday
                ? today : TaskDates.nextWeekday(weekday, after: today, calendar: calendar)
        }

        // "!" flags the task (anywhere, as its own word)
        for i in norm.indices where norm[i] == "!" || norm[i] == "!!" {
            result.flagged = true
            removed.insert(i)
        }

        // Last real word, ignoring a trailing "!"
        let lastIndex = norm.indices.last { !removed.contains($0) } ?? -1
        /// Short forms only count at the end or right after on/by/due.
        func shortFormAllowed(_ i: Int) -> Bool {
            i == lastIndex || (word(i - 1).map { datePrepositions.contains($0) } ?? false)
        }

        // "every …" sets a repeat (before dates, so "every monday" isn't read as a date)
        for i in norm.indices where word(i) == "every" {
            guard let next = word(i + 1) else { continue }
            var rule: TaskRepeat?
            switch next {
            case "day": rule = .daily
            case "weekday": rule = .weekdays
            case "week": rule = .weekly
            case "month": rule = .monthly
            default:
                if let wd = fullWeekdays[next] ?? shortWeekdays[next] {
                    rule = .weekly
                    result.due = upcoming(wd)
                }
            }
            if let rule = rule {
                result.repeatRule = rule
                removed.formUnion([i, i + 1])
                break
            }
        }

        // The first date
        if result.due == nil {
            for i in norm.indices {
                guard let w = word(i) else { continue }
                var date: Date?
                var span = 1

                switch w {
                case "today", "tonight":
                    date = today
                case "tomorrow":
                    date = addDays(1)
                case "tmr" where shortFormAllowed(i), "tmrw" where shortFormAllowed(i):
                    date = addDays(1)
                case "next":
                    if word(i + 1) == "week" {
                        date = TaskDates.nextWeekStart(now: now, calendar: calendar); span = 2
                    } else if let n = word(i + 1), let wd = fullWeekdays[n] ?? shortWeekdays[n] {
                        date = calendar.date(byAdding: .day, value: 7, to: upcoming(wd)); span = 2
                    }
                case "this":
                    if word(i + 1) == "weekend" {
                        date = TaskDates.thisWeekendDate(now: now, calendar: calendar); span = 2
                    }
                case "weekend" where shortFormAllowed(i):
                    date = TaskDates.thisWeekendDate(now: now, calendar: calendar)
                case "in":
                    // "in 3 days", "in 2 weeks"
                    if let n = word(i + 1).flatMap(Int.init), (1...365).contains(n), let unit = word(i + 2) {
                        if unit == "day" || unit == "days" { date = addDays(n); span = 3 }
                        if unit == "week" || unit == "weeks" { date = addDays(n * 7); span = 3 }
                    }
                default:
                    if let wd = fullWeekdays[w] {
                        date = upcoming(wd)
                    } else if let wd = shortWeekdays[w], shortFormAllowed(i) {
                        date = upcoming(wd)
                    } else if let (d, s) = dayMonth(at: i, word: word, today: today, calendar: calendar) {
                        date = d; span = s
                    }
                }

                if let date = date {
                    result.due = date
                    removed.formUnion(i..<(i + span))
                    if let prev = word(i - 1), datePrepositions.contains(prev) { removed.insert(i - 1) }
                    break
                }
            }
        }

        // A repeat with no date starts today
        if result.repeatRule != .never && result.due == nil { result.due = today }

        let title = words.indices.filter { !removed.contains($0) }.map { words[$0] }.joined(separator: " ")
        // Nothing left (e.g. just "tomorrow"): keep the text as typed
        guard !title.trimmingCharacters(in: .whitespaces).isEmpty else {
            return TaskQuickAdd(title: text.trimmingCharacters(in: .whitespaces))
        }
        result.title = title
        return result
    }

    /// "12 nov", "nov 12", "12th november" or "12/11" (day/month) → the next such date
    /// (this year, or next year if it has passed), with how many words it used.
    private static func dayMonth(at i: Int, word: (Int) -> String?, today: Date, calendar: Calendar) -> (Date, Int)? {
        func dayNumber(_ s: String?) -> Int? {
            guard var s = s else { return nil }
            for suffix in ["st", "nd", "rd", "th"] where s.hasSuffix(suffix) { s.removeLast(2) }
            guard let n = Int(s), (1...31).contains(n) else { return nil }
            return n
        }

        var day: Int?, month: Int?, span = 2
        if let d = dayNumber(word(i)), let m = word(i + 1).flatMap({ months[$0] }) {
            day = d; month = m
        } else if let m = word(i).flatMap({ months[$0] }), let d = dayNumber(word(i + 1)) {
            day = d; month = m
        } else if let w = word(i) {
            let parts = w.split(separator: "/")
            if parts.count == 2, let d = dayNumber(String(parts[0])), let m = Int(parts[1]), (1...12).contains(m) {
                day = d; month = m; span = 1
            }
        }
        guard let day = day, let month = month else { return nil }

        let year = calendar.component(.year, from: today)
        for y in [year, year + 1] {
            guard let date = calendar.date(from: DateComponents(year: y, month: month, day: day)),
                  calendar.component(.day, from: date) == day else { return nil }   // e.g. 31 nov
            if date >= today { return (date, span) }
        }
        return nil
    }
}
