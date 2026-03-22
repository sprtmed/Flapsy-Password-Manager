import Foundation
import os.log

private let logger = Logger(subsystem: "com.knox.app", category: "UpdateCheck")

final class UpdateCheckService: ObservableObject {
    @Published var updateAvailable = false
    @Published var latestVersion: String?

    private static let enabledKey = "com.knox.checkForUpdates"
    private let releasesURL = "https://api.github.com/repos/sprtmed/Knox-Password-Manager/releases/latest"
    private var hasChecked = false

    /// Read/write the opt-in preference via UserDefaults (available before vault unlock)
    static var isEnabled: Bool {
        get {
            // Default to true if key has never been set
            if UserDefaults.standard.object(forKey: enabledKey) == nil { return true }
            return UserDefaults.standard.bool(forKey: enabledKey)
        }
        set { UserDefaults.standard.set(newValue, forKey: enabledKey) }
    }

    /// Current app version from the built binary
    let currentVersion: String = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0"

    func checkForUpdate() {
        guard !hasChecked else { return }
        hasChecked = true
        guard Self.isEnabled else {
            logger.info("Update check disabled by user")
            return
        }

        Task.detached(priority: .utility) { [weak self] in
            guard let self else { return }
            do {
                guard let url = URL(string: self.releasesURL) else { return }
                var request = URLRequest(url: url)
                request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
                request.timeoutInterval = 10

                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return }

                struct Release: Decodable { let tag_name: String }
                let release = try JSONDecoder().decode(Release.self, from: data)

                // Strip leading "v" if present (e.g. "v1.1" → "1.1")
                let remote = release.tag_name.hasPrefix("v")
                    ? String(release.tag_name.dropFirst())
                    : release.tag_name

                let local = self.currentVersion
                let isNewer = self.compareVersions(remote, local)
                logger.info("Version check: local=\(local, privacy: .public) remote=\(remote, privacy: .public) newer=\(isNewer, privacy: .public)")

                await MainActor.run {
                    if isNewer {
                        self.updateAvailable = true
                        self.latestVersion = remote
                    }
                }
            } catch {
                logger.debug("Version check failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Determines if the user should be shown the update reminder.
    /// Suppresses the banner for 72 hours after dismissal to avoid nagging.
    private func shouldShowReminder() -> Bool {
        let dismissedKey = "com.knox.update.dismissedAt"
        let dismissedAt = UserDefaults.standard.double(forKey: dismissedKey)
        guard dismissedAt > 0 else { return true }
        let elapsed = Date().timeIntervalSince1970 - dismissedAt
        return elapsed > 259_200  // 72 hours
    }

    /// Simple semantic version comparison: returns true if `remote` > `local`
    private func compareVersions(_ remote: String, _ local: String) -> Bool {
        let r = remote.split(separator: ".").compactMap { Int($0) }
        let l = local.split(separator: ".").compactMap { Int($0) }
        let count = max(r.count, l.count)
        for i in 0..<count {
            let rv = i < r.count ? r[i] : 0
            let lv = i < l.count ? l[i] : 0
            if rv > lv { return true }
            if rv < lv { return false }
        }
        return false
    }
}
