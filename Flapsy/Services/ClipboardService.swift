import AppKit
import Foundation

final class ClipboardService {
    static let shared = ClipboardService()
    private var clearTimer: Timer?
    private var lastChangeCount: Int = 0

    /// Pasteboard type that signals to clipboard managers (1Password, KeePassXC,
    /// Paste, Alfred, etc.) that the content is sensitive and should not be recorded.
    private static let concealedType = NSPasteboard.PasteboardType(
        "org.nspasteboard.ConcealedType"
    )

    private init() {}

    /// Copies a string to the clipboard and optionally schedules auto-clear.
    /// Marks the content as "concealed" so well-behaved clipboard managers
    /// will not persist it in their history.
    func copy(_ string: String, clearAfter seconds: Int? = nil) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(string, forType: .string)
        // Mark as concealed — the value is irrelevant, only the type's presence matters
        pasteboard.setString("", forType: Self.concealedType)
        lastChangeCount = pasteboard.changeCount

        if let seconds = seconds, seconds > 0 {
            scheduleClear(after: seconds)
        }
    }

    /// Schedules the clipboard to be cleared after `seconds`.
    /// Only clears if the clipboard still holds the content we placed (avoids
    /// accidentally erasing something the user copied from another app).
    func scheduleClear(after seconds: Int) {
        clearTimer?.invalidate()
        let expectedCount = lastChangeCount
        clearTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(seconds), repeats: false) { _ in
            let pasteboard = NSPasteboard.general
            if pasteboard.changeCount == expectedCount {
                pasteboard.clearContents()
            }
        }
    }

    /// Cancels a pending clipboard clear.
    func cancelClear() {
        clearTimer?.invalidate()
        clearTimer = nil
    }

    /// Removes transient originator metadata that some clipboard managers use
    /// to track which application placed the current pasteboard content.
    private func stripOriginatorMetadata() {
        let pasteboard = NSPasteboard.general
        let transientTypes = [
            NSPasteboard.PasteboardType("com.apple.pasteboard.promised-type-identifiers"),
            NSPasteboard.PasteboardType("net.antelle.keeweb.clipboard-clear")
        ]
        for ptype in transientTypes {
            if pasteboard.data(forType: ptype) != nil {
                pasteboard.setData(Data(), forType: ptype)
            }
        }
    }

    /// Clears the clipboard immediately if it still holds content we placed,
    /// and cancels any pending auto-clear timer.
    func forceClearIfOwned() {
        clearTimer?.invalidate()
        clearTimer = nil
        let pasteboard = NSPasteboard.general
        if pasteboard.changeCount == lastChangeCount && lastChangeCount != 0 {
            pasteboard.clearContents()
        }
        lastChangeCount = 0
    }
}
