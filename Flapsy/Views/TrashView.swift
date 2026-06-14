import SwiftUI

struct TrashView: View {
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme
    @State private var showEmptyConfirmation = false

    var body: some View {
        VStack(spacing: 0) {
            if vault.trashedItems.isEmpty {
                emptyState
            } else {
                header
                itemList
            }
        }
        .alert("Empty Trash", isPresented: $showEmptyConfirmation) {
            Button("Delete All", role: .destructive) { vault.emptyTrash() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Permanently delete \(vault.trashedItems.count) item(s)? This cannot be undone.")
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "trash")
                .font(.system(size: 28))
                .foregroundColor(theme.textGhost)
            Text("Trash is empty")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(theme.textFaint)
            Text("Deleted items appear here for 30 days")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(theme.textGhost)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var header: some View {
        HStack {
            Text("\(vault.trashedItems.count) deleted item\(vault.trashedItems.count == 1 ? "" : "s")")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(theme.textFaint)
            Spacer()
            Button(action: { showEmptyConfirmation = true }) {
                Text("Empty Trash")
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundColor(theme.accentRed)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(theme.accentRed.opacity(0.1))
                    .cornerRadius(6)
            }
            .buttonStyle(.hand)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private var itemList: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(vault.trashedItems) { item in
                    trashRow(item)
                }
            }
        }
    }

    private func trashRow(_ item: VaultItem) -> some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(theme.fieldBg)
                    .frame(width: 36, height: 36)
                Group {
                    switch item.type {
                    case .card: Text("\u{1F4B3}").font(.system(size: 16))
                    case .note: Text("\u{1F4DD}").font(.system(size: 16))
                    case .login:
                        Circle()
                            .fill(theme.textGhost)
                            .frame(width: 12, height: 12)
                    }
                }
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                    .foregroundColor(theme.textSecondary)
                    .lineLimit(1)
                if let deletedAt = item.deletedAt {
                    Text(daysRemaining(deletedAt))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(theme.textGhost)
                }
            }

            Spacer()

            Button(action: { vault.restoreItem(item.id) }) {
                Image(systemName: "arrow.uturn.backward")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(theme.accentBlueLt)
                    .frame(width: 28, height: 28)
                    .background(theme.accentBlue.opacity(0.1))
                    .cornerRadius(6)
            }
            .buttonStyle(.hand)
            .help("Restore")

            Button(action: { vault.permanentlyDeleteItem(item.id) }) {
                Image(systemName: "xmark")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(theme.accentRed)
                    .frame(width: 28, height: 28)
                    .background(theme.accentRed.opacity(0.1))
                    .cornerRadius(6)
            }
            .buttonStyle(.hand)
            .help("Delete permanently")
        }
        .padding(.vertical, 9)
        .padding(.horizontal, 16)
    }

    private func daysRemaining(_ deletedAt: Date) -> String {
        let days = Int(ceil((deletedAt.addingTimeInterval(30 * 24 * 60 * 60).timeIntervalSince(Date())) / (24 * 60 * 60)))
        if days <= 0 { return "Expires soon" }
        if days == 1 { return "1 day left" }
        return "\(days) days left"
    }
}
