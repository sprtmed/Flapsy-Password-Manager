import SwiftUI

struct FlapsyTheme {
    let bg: Color
    let dropBg: Color
    let dropBorder: Color
    let text: Color
    let textSecondary: Color
    let textMuted: Color
    let textFaint: Color
    let textGhost: Color
    let textInvisible: Color
    let inputBg: Color
    let inputBorder: Color
    let fieldBg: Color
    let hoverBg: Color
    let activeBg: Color
    let pillBg: Color
    let toggleOff: Color
    let toggleThumb: Color
    let cardBg: Color
    let cardBorder: Color
    let accentBlue: Color
    let accentBlueLt: Color
    let accentPurple: Color
    let accentGreen: Color
    let accentYellow: Color
    let accentRed: Color
    let focusBorder: Color
    let selectionBg: Color
    let ddBg: Color
    let ddBorder: Color
    let ddItemHover: Color

    static let dark = FlapsyTheme(
        bg: Color(hex: "0c0c0e"),
        dropBg: Color(hex: "18181b"),
        dropBorder: Color.white.opacity(0.06),
        text: Color(hex: "e4e4e7"),
        textSecondary: Color(hex: "a1a1aa"),
        textMuted: Color(hex: "8a8a93"),
        textFaint: Color(hex: "6e6e78"),
        textGhost: Color(hex: "56565f"),
        textInvisible: Color(hex: "37373d"),
        inputBg: Color.white.opacity(0.05),
        inputBorder: Color.white.opacity(0.12),
        fieldBg: Color.white.opacity(0.04),
        hoverBg: Color.white.opacity(0.04),
        activeBg: Color(hex: "3b82f6").opacity(0.08),
        pillBg: Color(hex: "3b82f6").opacity(0.2),
        toggleOff: Color.white.opacity(0.1),
        toggleThumb: Color.white,
        cardBg: Color.white.opacity(0.04),
        cardBorder: Color.white.opacity(0.08),
        accentBlue: Color(hex: "3b82f6"),
        accentBlueLt: Color(hex: "60a5fa"),
        accentPurple: Color(hex: "a855f7"),
        accentGreen: Color(hex: "34d399"),
        accentYellow: Color(hex: "fbbf24"),
        accentRed: Color(hex: "f87171"),
        focusBorder: Color(hex: "3b82f6").opacity(0.4),
        selectionBg: Color(hex: "3b82f6").opacity(0.3),
        ddBg: Color(hex: "1e1e22"),
        ddBorder: Color.white.opacity(0.1),
        ddItemHover: Color.white.opacity(0.04)
    )

    static let light = FlapsyTheme(
        bg: Color(hex: "d8d8dc"),
        dropBg: Color(hex: "e2e2e6"),
        dropBorder: Color.black.opacity(0.10),
        text: Color(hex: "1a1a1f"),
        textSecondary: Color(hex: "46464f"),
        textMuted: Color(hex: "62626b"),
        textFaint: Color(hex: "8e8e97"),
        textGhost: Color(hex: "b5b5bd"),
        textInvisible: Color(hex: "c8c8cf"),
        inputBg: Color.black.opacity(0.06),
        inputBorder: Color.black.opacity(0.14),
        fieldBg: Color.black.opacity(0.04),
        hoverBg: Color.black.opacity(0.06),
        activeBg: Color(hex: "2563eb").opacity(0.10),
        pillBg: Color(hex: "2563eb").opacity(0.16),
        toggleOff: Color.black.opacity(0.16),
        toggleThumb: Color(hex: "f0f0f2"),
        cardBg: Color.black.opacity(0.04),
        cardBorder: Color.black.opacity(0.10),
        accentBlue: Color(hex: "2563eb"),
        accentBlueLt: Color(hex: "3b82f6"),
        accentPurple: Color(hex: "7c3aed"),
        accentGreen: Color(hex: "059669"),
        accentYellow: Color(hex: "d97706"),
        accentRed: Color(hex: "dc2626"),
        focusBorder: Color(hex: "2563eb").opacity(0.4),
        selectionBg: Color(hex: "2563eb").opacity(0.2),
        ddBg: Color(hex: "e2e2e6"),
        ddBorder: Color.black.opacity(0.12),
        ddItemHover: Color.black.opacity(0.06)
    )
}

// MARK: - Color Hex Init

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 6:
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8:
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}

// MARK: - Accessibility Helpers

extension FlapsyTheme {
    /// Computes perceptual luminance for WCAG 2.1 contrast ratio checks.
    /// Uses the sRGB linearization transfer function per W3C specification.
    static func relativeLuminance(hex: String) -> Double {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let r = Double((int >> 16) & 0xFF) / 255.0
        let g = Double((int >> 8) & 0xFF) / 255.0
        let b = Double(int & 0xFF) / 255.0
        func linearize(_ c: Double) -> Double {
            c <= 0.04045 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b)
    }
}

// MARK: - Theme Environment Key

struct ThemeKey: EnvironmentKey {
    static let defaultValue: FlapsyTheme = .dark
}

extension EnvironmentValues {
    var theme: FlapsyTheme {
        get { self[ThemeKey.self] }
        set { self[ThemeKey.self] = newValue }
    }
}

// MARK: - Category Colors

extension FlapsyTheme {
    func categoryColors(for key: String) -> (background: Color, foreground: Color) {
        categoryColors(hex: "8b5cf6")
    }

    func categoryColors(hex: String) -> (background: Color, foreground: Color) {
        let color = hex.isEmpty ? accentPurple : Color(hex: hex)
        return (color.opacity(0.12), color)
    }
}
