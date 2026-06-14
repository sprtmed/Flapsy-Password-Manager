import SwiftUI

struct ToastView: View {
    let message: String
    let totalSeconds: Int
    @Environment(\.theme) var theme

    @State private var remainingSeconds: Int = 0
    @State private var timer: Timer?

    var body: some View {
        Text("\(message) \u{00B7} clears in \(remainingSeconds)s")
            .font(.ui(10))
            .foregroundColor(theme.textMuted)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(theme.cardBg.opacity(0.9))
            .cornerRadius(12)
            .onAppear {
                remainingSeconds = totalSeconds
                startCountdown()
            }
            .onDisappear {
                timer?.invalidate()
                timer = nil
            }
    }

    private func startCountdown() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            if remainingSeconds > 0 {
                remainingSeconds -= 1
            } else {
                timer?.invalidate()
                timer = nil
            }
        }
    }
}
