import Foundation

/// Matches vault items against a website domain (from the active browser tab or a
/// domain-like search such as "sachs.com"). Pure logic, no state.
enum SiteMatcher {

    /// Second-level labels that form part of a country-code public suffix (e.g. co.uk, com.au).
    private static let secondLevelSuffixes: Set<String> = [
        "co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc", "ne", "or", "go",
    ]

    /// True for queries that look like a domain ("sachs.com"), where site matching applies.
    static func isDomainLike(_ query: String) -> Bool {
        query.contains(".") && !query.contains(" ")
    }

    /// "login.www.sachs.com" → "sachs.com"; "my.bank.co.uk" → "bank.co.uk".
    /// IP addresses and single-label hosts (localhost) are returned as-is.
    static func registrableDomain(forHost host: String) -> String {
        let host = host.lowercased()
        if host.allSatisfy({ $0.isNumber || $0 == "." || $0 == ":" }) || !host.contains(".") {
            return host
        }

        let labels = host.split(separator: ".").map(String.init)
        guard labels.count > 2 else { return host }

        let keep = (labels[labels.count - 1].count == 2 && secondLevelSuffixes.contains(labels[labels.count - 2])) ? 3 : 2
        return labels.suffix(keep).joined(separator: ".")
    }

    /// Host of a stored item URL, tolerating missing schemes ("sachs.com/login").
    static func host(fromItemURL string: String) -> String? {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let withScheme = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        return URL(string: withScheme)?.host?.lowercased()
    }

    /// How well `item` matches a domain-like `query`; nil = no site match. Higher is better.
    /// `browserHost` is the full host of the active tab when the query came from the browser.
    static func score(_ item: VaultItem, query: String, browserHost: String?) -> Int? {
        let query = query.lowercased()
        guard isDomainLike(query) else { return nil }

        let candidates = [item.url].compactMap { $0 } + (item.siteAliases ?? [])
        for candidate in candidates where candidate.lowercased().contains(query) {
            return 120
        }
        return nil
    }

    /// Whether `item` matches the browser site at all.
    static func matches(_ item: VaultItem, site: BrowserSite) -> Bool {
        score(item, query: site.domain, browserHost: site.host) != nil
    }
}
