import Foundation

/// Matches vault items against a website domain (from the active browser tab or a
/// domain-like search such as "sachs.com"). Pure logic, no state.
///
/// Ranking, best first (see `MatchKind`): exact host → same domain/tenant → equivalent
/// domain (shared account) → platform login on a tenant → item name spells the domain →
/// partial typed URL. Hosts are compared as hosts (never substrings), so "sachs.com" does
/// not match a login saved as "goldmansachs.com".
enum SiteMatcher {

    /// Why an item matched a site. The raw value is the score added to search ranking;
    /// every tier outranks incidental name/username/notes text matches (at most ~+65).
    enum MatchKind: Int, Comparable {
        /// Partial URL typed by hand ("goldmansachs.co"), never used for browser searches.
        case typedPartial = 60
        /// No website match, but the item name spells the domain ("Goldman Sachs" on goldmansachs.com).
        case name = 120
        /// The platform's own login on one of its tenants, or vice versa ("slack.com" on acme.slack.com).
        case platform = 150
        /// A different domain that shares one account ("amazon.de" on amazon.co.uk).
        case equivalent = 200
        /// Same registrable domain or tenant ("accounts.google.com" on mail.google.com).
        case sameDomain = 300
        /// A stored host equals the visited host, ignoring "www." ("mail.google.com").
        case exactHost = 400

        static func < (lhs: MatchKind, rhs: MatchKind) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    // MARK: - Curated Lists

    /// Second-level labels that form part of a country-code public suffix (e.g. co.uk, com.au).
    private static let secondLevelSuffixes: Set<String> = [
        "co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc", "ne", "or", "go",
    ]

    /// Multi-tenant platforms where each subdomain is a different company/account
    /// ("acme.atlassian.net" vs "globex.atlassian.net"). The label right before the suffix
    /// is the tenant and becomes part of the domain. Longest suffix wins.
    static let multiTenantSuffixes: [String] = [
        // Work tools
        "atlassian.net", "jira.com", "slack.com", "enterprise.slack.com", "zendesk.com",
        "freshdesk.com", "freshservice.com", "sharepoint.com", "my.salesforce.com",
        "lightning.force.com", "force.com", "my.site.com", "service-now.com", "monday.com",
        "bamboohr.com", "harvestapp.com", "okta.com", "oktapreview.com", "onelogin.com",
        "auth0.com", "awsapps.com", "cloudflareaccess.com", "myshopify.com",
        // Hosted sites & apps
        "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
        "notion.site", "blogspot.com", "wordpress.com", "azurewebsites.net", "webflow.io",
        "firebaseapp.com", "web.app", "appspot.com", "onrender.com", "fly.dev",
        "squarespace.com", "wixsite.com", "substack.com", "gitbook.io", "readthedocs.io",
    ].sorted { $0.count > $1.count }

    /// Subdomains of a platform that are the platform itself, not a tenant
    /// ("app.slack.com" is Slack's web client for every workspace).
    private static let reservedTenantLabels: Set<String> = [
        "www", "app", "apps", "api", "login", "signin", "auth", "sso", "id", "accounts",
        "account", "admin", "status", "help", "support", "docs", "blog", "mail", "community",
        "developer", "developers", "cdn", "static", "files",
    ]

    /// Domains that share one login (Bitwarden-style "equivalent domains"). Curated: only
    /// well-known shared accounts. Entries must be registrable domains as produced by
    /// `registrableDomain(forHost:)` (checked by the test harness).
    static let equivalentDomainGroups: [[String]] = [
        // Amazon country stores
        ["amazon.com", "amazon.co.uk", "amazon.ie", "amazon.de", "amazon.fr", "amazon.it",
         "amazon.es", "amazon.nl", "amazon.se", "amazon.pl", "amazon.com.be", "amazon.ca",
         "amazon.com.mx", "amazon.com.br", "amazon.com.au", "amazon.co.jp", "amazon.in",
         "amazon.sg", "amazon.ae", "amazon.sa", "amazon.com.tr", "amazon.eg"],
        ["apple.com", "icloud.com", "me.com"],
        ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "hotmail.com",
         "office.com", "office365.com", "microsoft365.com", "onedrive.com", "xbox.com",
         "skype.com", "msn.com", "azure.com", "bing.com"],
        ["google.com", "youtube.com", "gmail.com", "googlemail.com", "android.com", "blogger.com",
         "google.co.uk", "google.ie", "google.de", "google.fr", "google.es", "google.it",
         "google.nl", "google.ca", "google.com.au", "google.co.in", "google.co.jp",
         "google.com.br", "google.com.mx"],
        // eBay country sites
        ["ebay.com", "ebay.co.uk", "ebay.ie", "ebay.de", "ebay.fr", "ebay.it", "ebay.es",
         "ebay.nl", "ebay.be", "ebay.at", "ebay.ch", "ebay.pl", "ebay.ca", "ebay.com.au"],
        ["paypal.com", "paypal.me"],
        ["yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "ymail.com", "rocketmail.com"],
        ["facebook.com", "messenger.com", "fb.com"],
        ["twitter.com", "x.com"],
        ["atlassian.com", "atlassian.net", "bitbucket.org", "trello.com"],
        ["shopify.com", "myshopify.com"],
        ["salesforce.com", "force.com", "site.com"],
        ["adobe.com", "behance.net"],
        ["playstation.com", "sonyentertainmentnetwork.com"],
        ["steampowered.com", "steamcommunity.com"],
        ["epicgames.com", "unrealengine.com", "fortnite.com"],
        ["battle.net", "blizzard.com"],
        ["uber.com", "ubereats.com"],
    ]

    /// Domain → index of its group in `equivalentDomainGroups`.
    private static let equivalentGroupIndex: [String: Int] = {
        var index: [String: Int] = [:]
        for (i, group) in equivalentDomainGroups.enumerated() {
            for domain in group { index[domain] = i }
        }
        return index
    }()

    /// Leading words ignored by the name fallback ("My Goldman Sachs" → "goldmansachs").
    private static let leadingFillerWords: Set<String> = ["my", "the"]

    /// Shortest domain label the name fallback will match, so "go.com" or "x.com"
    /// don't surface every login named "Go…" or "X".
    private static let minNameLabelLength = 3

    // MARK: - Hosts & Domains

    /// True for queries that look like a domain ("sachs.com", "localhost:3000"), where site
    /// matching applies. Emails ("me@gmail.com") are excluded: that's a username search.
    static func isDomainLike(_ query: String) -> Bool {
        let looksLikeHost = query.contains(".") || query == "localhost" || query.hasPrefix("localhost:")
        return looksLikeHost && !query.contains(where: \.isWhitespace) && !query.contains("@")
    }

    /// "login.www.sachs.com" → "sachs.com"; "my.bank.co.uk" → "bank.co.uk";
    /// "jira.acme.atlassian.net" → "acme.atlassian.net" (multi-tenant platform keeps the tenant);
    /// "app.slack.com" → "slack.com" (reserved label = the platform itself).
    /// IP addresses and single-label hosts (localhost) are returned as-is.
    static func registrableDomain(forHost host: String) -> String {
        let host = cleanHost(host)
        if isIPOrSingleLabel(host) { return host }

        if let platform = platform(forHost: host) {
            if let tenant = platform.tenant { return "\(tenant).\(platform.suffix)" }
            return heuristicDomain(platform.suffix)
        }
        return heuristicDomain(host)
    }

    /// Host of a stored item URL, tolerating missing schemes and ports ("sachs.com:8443/login").
    /// Returns nil for non-web URLs (androidapp://, mailto:) and text that isn't a URL.
    static func host(fromItemURL string: String) -> String? {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains(where: \.isWhitespace) else { return nil }
        let withScheme = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let url = URL(string: withScheme),
              let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let rawHost = url.host else { return nil }
        let host = cleanHost(rawHost)
        // Percent-escapes mean the "host" was free text, not a hostname
        guard !host.isEmpty, !host.contains("%") else { return nil }
        return host
    }

    /// Lowercased, trimmed, without trailing dots ("Sachs.COM." → "sachs.com").
    private static func cleanHost(_ host: String) -> String {
        var host = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while host.hasSuffix(".") { host.removeLast() }
        return host
    }

    /// Host for exact comparison: "www.sachs.com" and "sachs.com" are the same site.
    private static func comparableHost(_ host: String) -> String {
        let host = cleanHost(host)
        guard host.hasPrefix("www."), host.dropFirst(4).contains(".") else { return host }
        return String(host.dropFirst(4))
    }

    private static func isIPOrSingleLabel(_ host: String) -> Bool {
        host.contains(":")                                          // IPv6
            || host.allSatisfy({ $0.isNumber || $0 == "." })        // IPv4
            || !host.contains(".")                                  // localhost, intranet names
    }

    /// Last two labels, or three for country-code second levels ("bank.co.uk").
    private static func heuristicDomain(_ host: String) -> String {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count > 2 else { return host }
        let keep = (labels[labels.count - 1].count == 2 && secondLevelSuffixes.contains(labels[labels.count - 2])) ? 3 : 2
        return labels.suffix(keep).joined(separator: ".")
    }

    /// The multi-tenant platform `host` belongs to, with its tenant label
    /// (nil tenant = the platform itself, e.g. "slack.com" or "app.slack.com").
    private static func platform(forHost host: String) -> (suffix: String, tenant: String?)? {
        for suffix in multiTenantSuffixes {
            if host == suffix { return (suffix, nil) }
            guard host.hasSuffix("." + suffix) else { continue }

            let rest = host.dropLast(suffix.count + 1)
            var tenant = String(rest.split(separator: ".").last ?? "")
            // OneDrive/admin sites of a SharePoint tenant: "acme-my" / "acme-admin" → "acme"
            if suffix == "sharepoint.com" {
                for variant in ["-my", "-admin"] where tenant.hasSuffix(variant) && tenant.count > variant.count {
                    tenant.removeLast(variant.count)
                }
            }
            if tenant.isEmpty || reservedTenantLabels.contains(tenant) { return (suffix, nil) }
            return (suffix, tenant)
        }
        return nil
    }

    /// For a tenant domain ("acme.slack.com"), the platform's own domain ("slack.com"); nil otherwise.
    private static func platformRoot(ofTenantDomain domain: String) -> String? {
        guard let platform = platform(forHost: domain), platform.tenant != nil else { return nil }
        return heuristicDomain(platform.suffix)
    }

    /// Whether two different domains share one account ("amazon.de" / "amazon.co.uk").
    static func areEquivalent(_ a: String, _ b: String) -> Bool {
        guard a != b, let groupA = equivalentGroupIndex[a] else { return false }
        return groupA == equivalentGroupIndex[b]
    }

    /// Platform login vs tenant ("slack.com" vs "acme.slack.com", "shopify.com" vs
    /// "acme.myshopify.com" via equivalents). Two *different* tenants never match: they are
    /// separate companies. A login saved as the bare platform domain does match its tenants,
    /// at the low `.platform` tier, because many platforms sign in centrally (id.atlassian.com,
    /// accounts.shopify.com, app.slack.com) and that login is the one the user needs there.
    private static func isPlatformRelated(_ itemDomain: String, _ siteDomain: String) -> Bool {
        switch (platformRoot(ofTenantDomain: itemDomain), platformRoot(ofTenantDomain: siteDomain)) {
        case (nil, let siteRoot?):
            return itemDomain == siteRoot || areEquivalent(itemDomain, siteRoot)
        case (let itemRoot?, nil):
            return siteDomain == itemRoot || areEquivalent(siteDomain, itemRoot)
        default:
            return false
        }
    }

    // MARK: - Name Fallback

    /// The domain's main label for name matching: "goldmansachs" (goldmansachs.com),
    /// "bank" (bank.co.uk), "acme" (acme.atlassian.net), "marksandspencer" (marks-and-spencer.com).
    /// Nil for IPs, single-label hosts and labels too short to match safely.
    private static func mainLabel(ofDomain domain: String) -> String? {
        guard !isIPOrSingleLabel(domain) else { return nil }
        var labels = domain.split(separator: ".").map(String.init)
        if labels.first == "www", labels.count > 2 { labels.removeFirst() }
        guard let first = labels.first else { return nil }
        let label = first.replacingOccurrences(of: "-", with: "")
        guard label.count >= minNameLabelLength, !label.allSatisfy(\.isNumber) else { return nil }
        return label
    }

    /// Normalized name words, in two variants so "Marks & Spencer" → "marksandspencer" and
    /// "AT&T" → "att" both work. Lowercased, diacritics folded, punctuation dropped.
    private static func nameWordVariants(_ name: String) -> [[String]] {
        let folded = name.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
            .lowercased()
        return [folded.replacingOccurrences(of: "&", with: " and "), folded.replacingOccurrences(of: "&", with: "")]
            .map { text in
                var words = text.split(whereSeparator: { !($0.isLetter || $0.isNumber) }).map(String.init)
                while words.count > 1, let first = words.first, leadingFillerWords.contains(first) {
                    words.removeFirst()
                }
                return words
            }
    }

    /// True when the leading words of `name`, joined, spell `label` exactly:
    /// "Goldman Sachs" / "GoldmanSachs Login" → "goldmansachs"; "Revenue Online Service" → "revenue".
    /// Whole words only, so "Aibell" doesn't match "aib" and "Goldman Sachs" doesn't match "sachs".
    private static func name(_ name: String, spells label: String) -> Bool {
        for words in nameWordVariants(name) {
            var joined = ""
            for word in words {
                joined += word
                if joined == label { return true }
                if joined.count >= label.count || !label.hasPrefix(joined) { break }
            }
        }
        return false
    }

    // MARK: - Typed Partial Fallback

    /// "https://www.Sachs.com/login" → "sachs.com/login".
    private static func strippedURL(_ string: String) -> String {
        var text = string.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let range = text.range(of: "://") { text = String(text[range.upperBound...]) }
        if text.hasPrefix("www.") { text = String(text.dropFirst(4)) }
        return text
    }

    /// `needle` occurs in `text` at the start or right after "." or "/", so "goldmansachs.co"
    /// and "login.goldman" find "login.goldmansachs.com" but "sachs.com" does not.
    private static func containsAtLabelStart(_ text: String, _ needle: String) -> Bool {
        guard !needle.isEmpty else { return false }
        var searchRange = text.startIndex..<text.endIndex
        while let found = text.range(of: needle, range: searchRange) {
            if found.lowerBound == text.startIndex || "./".contains(text[text.index(before: found.lowerBound)]) {
                return true
            }
            searchRange = text.index(after: found.lowerBound)..<text.endIndex
        }
        return false
    }

    // MARK: - Scoring

    /// A domain-like query resolved once per call.
    private struct Site {
        /// Host being looked at (browser host, or the host typed), "www." removed.
        let host: String
        let domain: String
        /// Main label for the name fallback (nil = no name matching).
        let label: String?
        /// Typed text for the partial fallback; nil when the query came from the browser.
        let typed: String?

        init?(query: String, browserHost: String?) {
            let query = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard SiteMatcher.isDomainLike(query), let queryHost = SiteMatcher.host(fromItemURL: query) else {
                return nil
            }
            let queryDomain = SiteMatcher.registrableDomain(forHost: queryHost)

            // Use the browser's full host only if the query really is that site's domain
            if let browserHost = browserHost.map(SiteMatcher.cleanHost), !browserHost.isEmpty,
               SiteMatcher.registrableDomain(forHost: browserHost) == queryDomain {
                host = SiteMatcher.comparableHost(browserHost)
                typed = nil
            } else {
                host = SiteMatcher.comparableHost(queryHost)
                typed = SiteMatcher.strippedURL(query)
            }
            domain = queryDomain
            label = SiteMatcher.mainLabel(ofDomain: queryDomain)
        }
    }

    /// Best way `item` matches a domain-like `query`; nil = no site match.
    /// `browserHost` is the full host of the active tab when the query came from the browser
    /// (pre-filled, untouched); then the typed-partial fallback is off.
    static func matchKind(_ item: VaultItem, query: String, browserHost: String?) -> MatchKind? {
        guard let site = Site(query: query, browserHost: browserHost) else { return nil }

        var best: MatchKind?
        func consider(_ kind: MatchKind) {
            if best.map({ kind > $0 }) ?? true { best = kind }
        }

        let candidates = [item.url].compactMap { $0 } + (item.siteAliases ?? [])
        for candidate in candidates {
            if let host = host(fromItemURL: candidate) {
                if comparableHost(host) == site.host { return .exactHost }

                let domain = registrableDomain(forHost: host)
                if domain == site.domain {
                    consider(.sameDomain)
                } else if areEquivalent(domain, site.domain) {
                    consider(.equivalent)
                } else if isPlatformRelated(domain, site.domain) {
                    consider(.platform)
                }
            }
            if let typed = site.typed, containsAtLabelStart(strippedURL(candidate), typed) {
                consider(.typedPartial)
            }
        }

        // Name fallback only when no website match was found (it ranks below them anyway)
        if best.map({ $0 < .name }) ?? true, let label = site.label, name(item.name, spells: label) {
            consider(.name)
        }
        return best
    }

    /// How well `item` matches a domain-like `query`; nil = no site match. Higher is better
    /// (the `MatchKind` tier score). `browserHost` is the full host of the active tab when
    /// the query came from the browser.
    static func score(_ item: VaultItem, query: String, browserHost: String?) -> Int? {
        matchKind(item, query: query, browserHost: browserHost)?.rawValue
    }

    /// Whether `item` matches the browser site at all (any tier, including the name fallback).
    static func matches(_ item: VaultItem, site: BrowserSite) -> Bool {
        score(item, query: site.domain, browserHost: site.host) != nil
    }
}
