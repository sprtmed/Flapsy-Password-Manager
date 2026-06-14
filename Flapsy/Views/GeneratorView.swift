import SwiftUI

struct GeneratorView: View {
    @StateObject private var generator = GeneratorViewModel()
    @EnvironmentObject var vault: VaultViewModel
    @Environment(\.theme) var theme

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                topButtons
                passwordDisplay

                if !generator.generatedPassword.isEmpty {
                    strengthBar
                } else {
                    Spacer().frame(height: 20)
                }

                Divider()
                    .background(theme.cardBorder)
                    .padding(.bottom, 16)

                // Type selector with FlapsyDropdown
                settingRow("Type") {
                    FlapsyDropdown(
                        value: generator.generatorType.rawValue,
                        options: GeneratorType.allCases.map(\.rawValue),
                        onChange: { val in
                            if let type = GeneratorType(rawValue: val) {
                                generator.generatorType = type
                                generator.generatedPassword = ""
                            }
                        },
                        width: 190
                    )
                }
                .zIndex(10)

                // Type-specific controls
                switch generator.generatorType {
                case .random:
                    randomControls
                case .memorable:
                    memorableControls
                case .pin:
                    pinControls
                }

            }
            .padding(16)
        }
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }

    // MARK: - Top Buttons

    private var topButtons: some View {
        HStack(spacing: 6) {
            Button(action: { generator.generate() }) {
                Text("\u{21BB}")
                    .font(.system(size: 14))
                    .foregroundColor(theme.textSecondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(theme.fieldBg)
                    .cornerRadius(6)
            }
            .buttonStyle(.hand)

            Spacer()

            Button(action: { generator.generate() }) {
                Text("Autofill")
                    .font(.ui(12, weight: .semibold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 6)
                    .background(
                        LinearGradient(
                            colors: [Color(hex: "3b82f6"), Color(hex: "2563eb")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .cornerRadius(8)
            }
            .buttonStyle(.hand)
        }
        .padding(.bottom, 8)
    }

    // MARK: - Password Display

    private var passwordDisplay: some View {
        HStack {
            if generator.isGenerating {
                Text("generating\u{2026}")
                    .font(.ui(14))
                    .foregroundColor(theme.textFaint)
                    .opacity(0.6)
            } else if generator.generatedPassword.isEmpty {
                Text("Click \u{21BB} or Autofill")
                    .font(.ui(14))
                    .foregroundColor(theme.textGhost)
            } else {
                Text(generator.generatedPassword)
                    .font(.mono(14))
                    .foregroundColor(theme.text)
                    .lineLimit(nil)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if !generator.generatedPassword.isEmpty {
                IconButton(
                    icon: generator.copied ? "checkmark" : "doc.on.doc",
                    isActive: generator.copied,
                    action: { generator.copyGenerated() }
                )
            }
        }
        .padding(12)
        .frame(minHeight: 48)
        .background(theme.fieldBg)
        .cornerRadius(8)
        .padding(.bottom, 4)
    }

    // MARK: - Strength Bar

    private var strengthBar: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 2)
                    .fill(theme.fieldBg)
                RoundedRectangle(cornerRadius: 2)
                    .fill(PasswordStrength.color(for: generator.strength))
                    .frame(width: geo.size.width * CGFloat(generator.strength) / 100)
                    .animation(.easeInOut(duration: 0.3), value: generator.strength)
            }
        }
        .frame(height: 4)
        .padding(.bottom, 16)
    }

    // MARK: - Random Controls

    @ViewBuilder
    private var randomControls: some View {
        sliderRow(
            label: "Characters",
            value: $generator.characterCount,
            range: 12...50,
            step: 1,
            displayValue: "\(Int(generator.characterCount))"
        )

        settingRow("Numbers") {
            FlapsyToggle(isOn: $generator.includeNumbers)
        }

        settingRow("Symbols") {
            FlapsyToggle(isOn: $generator.includeSymbols)
        }
    }

    // MARK: - Memorable Controls

    @ViewBuilder
    private var memorableControls: some View {
        sliderRow(
            label: "Words",
            value: $generator.wordCount,
            range: 2...8,
            step: 1,
            displayValue: "\(Int(generator.wordCount))"
        )

        settingRow("Separator") {
            FlapsyDropdown(
                value: generator.separator.rawValue,
                options: SeparatorType.allCases.map(\.rawValue),
                onChange: { val in
                    if let sep = SeparatorType(rawValue: val) {
                        generator.separator = sep
                    }
                },
                width: 140
            )
        }
        .zIndex(5)

        settingRow("Capitalize") {
            FlapsyToggle(isOn: $generator.capitalize)
        }

        settingRow("Full Words") {
            FlapsyToggle(isOn: $generator.fullWords)
        }
    }

    // MARK: - PIN Controls

    @ViewBuilder
    private var pinControls: some View {
        sliderRow(
            label: "Digits",
            value: $generator.pinLength,
            range: 4...12,
            step: 1,
            displayValue: "\(Int(generator.pinLength))"
        )
    }

    // MARK: - Helpers

    private func settingRow<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        HStack {
            Text(label)
                .font(.ui(13))
                .foregroundColor(theme.text)
            Spacer()
            content()
        }
        .padding(.vertical, 10)
    }

    private func sliderRow(label: String, value: Binding<Double>, range: ClosedRange<Double>, step: Double, displayValue: String) -> some View {
        VStack(spacing: 8) {
            HStack {
                Text(label)
                    .font(.ui(13))
                    .foregroundColor(theme.text)
                Spacer()
                Text(displayValue)
                    .font(.ui(13, weight: .semibold))
                    .foregroundColor(theme.accentBlueLt)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 2)
                    .background(theme.accentBlue.opacity(0.08))
                    .cornerRadius(6)
            }
            Slider(value: value, in: range, step: step)
                .tint(theme.accentBlue)
        }
        .padding(.vertical, 10)
    }
}
