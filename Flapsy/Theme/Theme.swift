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

    // Palette from designer token set (indigo accent, warm charcoal surfaces).
    static let dark = FlapsyTheme(
        bg: Color(hex: "1d1d22"),                       // --canvas
        dropBg: Color(hex: "26262d"),                   // --surface (flattened) / --surface-solid
        dropBorder: Color(hex: "42424c"),               // --hairline-strong
        text: Color(hex: "f2f2f5"),                     // --ink
        textSecondary: Color(hex: "b4b4c0"),
        textMuted: Color(hex: "9c9caa"),                // --muted
        textFaint: Color(hex: "74747f"),                // --faint
        textGhost: Color(hex: "5a5a63"),
        textInvisible: Color(hex: "42424c"),
        inputBg: Color(hex: "33333c"),                  // --field
        inputBorder: Color(hex: "42424c"),              // --hairline-strong
        fieldBg: Color(hex: "33333c"),                  // --field
        hoverBg: Color(hex: "8b8bf2").opacity(0.10),    // --row-hover
        activeBg: Color(hex: "2c2c4a"),                 // --accent-soft
        pillBg: Color(hex: "2c2c4a"),                   // --accent-soft
        toggleOff: Color.white.opacity(0.1),
        toggleThumb: Color.white,
        cardBg: Color(hex: "2f2f37"),                   // --raise
        cardBorder: Color(hex: "36363f"),               // --hairline
        accentBlue: Color(hex: "8b8bf2"),               // --accent
        accentBlueLt: Color(hex: "aeaef8"),             // --accent-ink
        accentPurple: Color(hex: "a78bea"),
        accentGreen: Color(hex: "4cc47e"),              // --good
        accentYellow: Color(hex: "e0a83f"),             // --warn
        accentRed: Color(hex: "ef6259"),                // --bad
        focusBorder: Color(hex: "8b8bf2").opacity(0.4),
        selectionBg: Color(hex: "8b8bf2").opacity(0.3),
        ddBg: Color(hex: "26262d"),                     // --surface-solid
        ddBorder: Color(hex: "36363f"),                 // --hairline
        ddItemHover: Color(hex: "8b8bf2").opacity(0.10)
    )

    static let light = FlapsyTheme(
        bg: Color(hex: "f4f4f7"),                       // --canvas
        dropBg: Color(hex: "eef0fa"),                   // --surface over periwinkle, flattened
        dropBorder: Color(hex: "dcdce4"),               // --hairline-strong
        text: Color(hex: "1b1b22"),                     // --ink
        textSecondary: Color(hex: "5b5b66"),
        textMuted: Color(hex: "75757f"),                // --muted
        textFaint: Color(hex: "9a9aa6"),                // --faint
        textGhost: Color(hex: "b9b9c2"),
        textInvisible: Color(hex: "d2d2da"),
        inputBg: Color(hex: "e9eaf2"),                  // --field (cooled for lavender surface)
        inputBorder: Color(hex: "dcdce4"),              // --hairline-strong
        fieldBg: Color(hex: "e9eaf2"),                  // --field
        hoverBg: Color(hex: "5b5bd6").opacity(0.06),    // --row-hover
        activeBg: Color(hex: "ecedfb"),                 // --accent-soft
        pillBg: Color(hex: "ecedfb"),                   // --accent-soft
        toggleOff: Color.black.opacity(0.16),
        toggleThumb: Color(hex: "ffffff"),
        cardBg: Color(hex: "ffffff"),                   // --raise / --surface-solid
        cardBorder: Color(hex: "e6e6ee"),               // --hairline
        accentBlue: Color(hex: "5b5bd6"),               // --accent
        accentBlueLt: Color(hex: "7676e4"),
        accentPurple: Color(hex: "8a6bea"),             // crest gradient stop
        accentGreen: Color(hex: "1f9d57"),              // --good
        accentYellow: Color(hex: "c2861a"),             // --warn
        accentRed: Color(hex: "d6423a"),                // --bad
        focusBorder: Color(hex: "5b5bd6").opacity(0.4),
        selectionBg: Color(hex: "5b5bd6").opacity(0.2),
        ddBg: Color(hex: "ffffff"),                     // --surface-solid
        ddBorder: Color(hex: "e6e6ee"),                 // --hairline
        ddItemHover: Color(hex: "5b5bd6").opacity(0.06)
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
