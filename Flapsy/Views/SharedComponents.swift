import SwiftUI

// MARK: - Pointing-Hand Cursor

/// Button style that behaves like `.plain` but shows the pointing-hand cursor on hover.
/// Use `.buttonStyle(.hand)` in place of `.buttonStyle(.hand)`.
struct HandButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HandButtonBody(configuration: configuration)
    }

    private struct HandButtonBody: View {
        let configuration: ButtonStyle.Configuration
        @State private var hovering = false

        var body: some View {
            configuration.label
                .opacity(configuration.isPressed ? 0.7 : 1)
                .onHover { h in
                    hovering = h
                    if h { NSCursor.pointingHand.push() } else { NSCursor.pop() }
                }
                .onDisappear {
                    // Avoid a stuck cursor if the view is removed while hovered.
                    if hovering { NSCursor.pop(); hovering = false }
                }
        }
    }
}

extension ButtonStyle where Self == HandButtonStyle {
    static var hand: HandButtonStyle { HandButtonStyle() }
}

/// Adds the pointing-hand cursor on hover to non-Button clickable views
/// (e.g. rows and toggles driven by `.onTapGesture`).
struct HandCursorModifier: ViewModifier {
    @State private var hovering = false

    func body(content: Content) -> some View {
        content
            .onHover { h in
                hovering = h
                if h { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }
            .onDisappear {
                if hovering { NSCursor.pop(); hovering = false }
            }
    }
}

extension View {
    func handCursor() -> some View { modifier(HandCursorModifier()) }
}

// MARK: - FlapsyToggle

/// Custom toggle matching the mockup: 44x26px track, 20x20 thumb, spring animation.
struct FlapsyToggle: View {
    @Binding var isOn: Bool
    var accentColor: Color? = nil
    @Environment(\.theme) var theme

    var body: some View {
        let resolvedAccent = accentColor ?? theme.accentBlue

        ZStack(alignment: isOn ? .trailing : .leading) {
            // Track
            RoundedRectangle(cornerRadius: 13)
                .fill(isOn ? resolvedAccent : theme.toggleOff)
                .frame(width: 44, height: 26)
                .shadow(
                    color: isOn ? resolvedAccent.opacity(0.27) : Color.clear,
                    radius: 4, y: 0
                )

            // Thumb
            Circle()
                .fill(theme.toggleThumb)
                .frame(width: 20, height: 20)
                .shadow(color: Color.black.opacity(0.3), radius: 1.5, y: 1)
                .padding(3)
        }
        .frame(width: 44, height: 26)
        .onTapGesture {
            withAnimation(.spring(response: 0.2, dampingFraction: 0.64)) {
                isOn.toggle()
            }
        }
        .handCursor()
    }
}

// MARK: - FlapsyDropdown

/// Custom dropdown matching the mockup style with themed overlay menu.
struct FlapsyDropdown: View {
    let value: String
    let options: [String]
    let onChange: (String) -> Void
    var width: CGFloat = 180

    @Environment(\.theme) var theme
    @State private var isOpen = false

    var body: some View {
        ZStack(alignment: .topLeading) {
            // Trigger button
            Button(action: { withAnimation(.easeOut(duration: 0.15)) { isOpen.toggle() } }) {
                HStack {
                    Text(value)
                        .font(.ui(12))
                        .foregroundColor(theme.text)
                    Spacer()
                    Text("▼")
                        .font(.system(size: 8))
                        .foregroundColor(theme.textMuted)
                        .rotationEffect(.degrees(isOpen ? 180 : 0))
                        .animation(.easeInOut(duration: 0.2), value: isOpen)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(theme.inputBg)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(isOpen ? theme.focusBorder : theme.inputBorder, lineWidth: 1)
                )
            }
            .buttonStyle(.hand)
            .frame(width: width)
        }
        .overlay(alignment: .top) {
            if isOpen {
                dropdownMenu
                    .offset(y: 38)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .zIndex(isOpen ? 50 : 0)
    }

    private var dropdownMenu: some View {
        VStack(spacing: 0) {
            ForEach(options, id: \.self) { opt in
                Button(action: {
                    onChange(opt)
                    withAnimation(.easeOut(duration: 0.15)) { isOpen = false }
                }) {
                    HStack {
                        Text(opt)
                            .font(.ui(12))
                            .foregroundColor(opt == value ? theme.accentBlueLt : theme.textSecondary)
                        Spacer()
                        if opt == value {
                            Text("✓")
                                .font(.system(size: 11))
                                .foregroundColor(theme.accentBlue)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 9)
                    .background(opt == value ? theme.activeBg : Color.clear)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.hand)
            }
        }
        .background(theme.ddBg)
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(theme.ddBorder, lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.3), radius: 20, y: 6)
        .frame(width: width)
    }
}

// MARK: - PlainTextEditor

/// An NSTextView wrapper that forces plain-text-only editing.
/// Pasted HTML / rich text is automatically stripped to plain text.
struct PlainTextEditor: NSViewRepresentable {
    @Binding var text: String
    var font: NSFont = .monospacedSystemFont(ofSize: 13, weight: .regular)
    var textColor: NSColor = .labelColor
    var insertionPointColor: NSColor = .labelColor

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.drawsBackground = false
        scrollView.borderType = .noBorder

        let textView = PlainNSTextView()
        textView.delegate = context.coordinator
        textView.isEditable = true
        textView.isSelectable = true
        textView.isRichText = false
        textView.importsGraphics = false
        textView.allowsUndo = true
        textView.drawsBackground = false
        textView.font = font
        textView.textColor = textColor
        textView.insertionPointColor = insertionPointColor
        textView.textContainerInset = NSSize(width: 0, height: 0)
        textView.textContainer?.widthTracksTextView = true
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.string = text

        scrollView.documentView = textView
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let textView = scrollView.documentView as? NSTextView else { return }
        if textView.string != text {
            textView.string = text
            textView.font = font
            textView.textColor = textColor
        }
        textView.font = font
        textView.textColor = textColor
        textView.insertionPointColor = insertionPointColor
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: PlainTextEditor
        init(_ parent: PlainTextEditor) { self.parent = parent }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            parent.text = textView.string
        }
    }
}

/// NSTextView subclass that strips rich text on paste.
final class PlainNSTextView: NSTextView {
    override func paste(_ sender: Any?) {
        pasteAsPlainText(sender)
    }
}
