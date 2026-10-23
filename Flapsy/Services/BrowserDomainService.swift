import AppKit
import Foundation
import os.log

private let logger = Logger(subsystem: "com.knox.app", category: "BrowserDomain")

/// The website the user was on when they opened Flapsy.
struct BrowserSite: Equatable {
    /// Full host of the active tab, e.g. "login.goldmansachs.com".
    let host: String
    /// Domain used for search, e.g. "goldmansachs.com".
    let domain: String
}

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

    /// Apple Events block until the target replies (and on first use until the user
    /// answers the consent prompt), so scripts run off the main thread, one at a time.
    private let queue = DispatchQueue(label: "com.knox.app.browser-domain")

    private init() {}

    /// Whether the given app is a browser we can query.
    func isSupportedBrowser(_ app: NSRunningApplication?) -> Bool {
        guard let id = app?.bundleIdentifier else { return false }
        return Self.supportedBrowsers[id] != nil
    }

    /// Asynchronously fetches the active tab's site from `app`.
    /// Calls `completion` on the main thread with the site, or nil.
    func fetchSite(from app: NSRunningApplication?, completion: @escaping (BrowserSite?) -> Void) {
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
            let site = result?.stringValue.flatMap(Self.site(fromURL:))
            DispatchQueue.main.async { completion(site) }
        }
    }

    /// "https://login.sachs.com/path" → BrowserSite(host: "login.sachs.com", domain: "sachs.com");
    /// "https://jira.acme.atlassian.net" → domain "acme.atlassian.net" (multi-tenant platforms keep the tenant).
    /// Returns nil for non-web pages (new tab, about:blank, file://, favorites://).
    static func site(fromURL string: String) -> BrowserSite? {
        guard let url = URL(string: string),
              let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              var host = url.host?.lowercased() else { return nil }
        // "example.com." (fully qualified) is the same site as "example.com"
        while host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty else { return nil }
        return BrowserSite(host: host, domain: SiteMatcher.registrableDomain(forHost: host))
    }
}
