import AppKit
import Foundation
import os.log

private let logger = Logger(subsystem: "com.knox.app", category: "BrowserDomain")

/// Reads the domain of the active tab in the frontmost browser via Apple Events,
/// so the vault search can be pre-filled with it. macOS asks the user once per
/// browser ("Flapsy wants to control Safari"); if denied, lookups just return nil.
final class BrowserDomainService {
    static let shared = BrowserDomainService()

    /// Bundle ID → AppleScript property path for the active tab's URL.
    /// Safari uses "current tab"; Chromium-based browsers use "active tab".
    private static let supportedBrowsers: [String: String] = [
        "com.apple.Safari": "URL of current tab of front window",
        "com.apple.SafariTechnologyPreview": "URL of current tab of front window",
        "com.google.Chrome": "URL of active tab of front window",
        "com.google.Chrome.beta": "URL of active tab of front window",
        "com.brave.Browser": "URL of active tab of front window",
        "com.microsoft.edgemac": "URL of active tab of front window",
        "com.vivaldi.Vivaldi": "URL of active tab of front window",
        "company.thebrowser.Browser": "URL of active tab of front window",
    ]

    /// Second-level labels that form part of a country-code public suffix (e.g. co.uk, com.au).
    private static let secondLevelSuffixes: Set<String> = [
        "co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc", "ne", "or", "go",
    ]

    /// Apple Events block until the target replies (and on first use until the user
    /// answers the consent prompt), so scripts run off the main thread, one at a time.
    private let queue = DispatchQueue(label: "com.knox.app.browser-domain")

    private init() {}

    /// Whether the given app is a browser we can query.
    func isSupportedBrowser(_ app: NSRunningApplication?) -> Bool {
        guard let id = app?.bundleIdentifier else { return false }
        return Self.supportedBrowsers[id] != nil
    }

    /// Asynchronously fetches the active tab's domain from `app`.
    /// Calls `completion` on the main thread with e.g. "sachs.com", or nil.
    func fetchDomain(from app: NSRunningApplication?, completion: @escaping (String?) -> Void) {
        guard let bundleID = app?.bundleIdentifier,
              let urlPath = Self.supportedBrowsers[bundleID] else {
            completion(nil)
            return
        }

        let source = """
        tell application id "\(bundleID)"
            with timeout of 2 seconds
                if (count of windows) is 0 then return ""
                return \(urlPath)
            end timeout
        end tell
        """

        queue.async {
            var error: NSDictionary?
            let result = NSAppleScript(source: source)?.executeAndReturnError(&error)
            if let error = error {
                logger.info("Browser URL lookup failed: \(error[NSAppleScript.errorNumber] as? Int ?? 0, privacy: .public)")
            }
            let domain = result?.stringValue.flatMap(Self.domain(fromURL:))
            DispatchQueue.main.async { completion(domain) }
        }
    }

    /// "https://login.www.sachs.com/path" → "sachs.com"; "https://my.bank.co.uk" → "bank.co.uk".
    /// Returns nil for non-web pages (new tab, about:blank, file://, favorites://).
    static func domain(fromURL string: String) -> String? {
        guard let url = URL(string: string),
              let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = url.host?.lowercased(), !host.isEmpty else { return nil }

        // IP addresses and single-label hosts (localhost) are used as-is
        if host.allSatisfy({ $0.isNumber || $0 == "." || $0 == ":" }) || !host.contains(".") {
            return host
        }

        let labels = host.split(separator: ".").map(String.init)
        guard labels.count > 2 else { return host }

        let keep = (labels[labels.count - 1].count == 2 && secondLevelSuffixes.contains(labels[labels.count - 2])) ? 3 : 2
        return labels.suffix(keep).joined(separator: ".")
    }
}
