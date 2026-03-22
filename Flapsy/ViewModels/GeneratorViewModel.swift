import Foundation
import Combine
import Security

enum GeneratorType: String, CaseIterable {
    case random = "Random Password"
    case memorable = "Memorable Password"
    case pin = "PIN Code"
}

enum SeparatorType: String, CaseIterable {
    case hyphens = "Hyphens"
    case periods = "Periods"
    case spaces = "Spaces"
    case commas = "Commas"
    case underscores = "Underscores"
    case numbers = "Numbers"

    var character: String {
        switch self {
        case .hyphens: return "-"
        case .periods: return "."
        case .spaces: return " "
        case .commas: return ","
        case .underscores: return "_"
        case .numbers: return "" // handled specially
        }
    }
}

final class GeneratorViewModel: ObservableObject {
    @Published var generatorType: GeneratorType = .random
    @Published var generatedPassword: String = ""
    @Published var isGenerating: Bool = false
    @Published var copied: Bool = false

    // Random Password settings
    @Published var characterCount: Double = 20
    @Published var includeNumbers: Bool = true
    @Published var includeSymbols: Bool = true

    // Memorable Password settings
    @Published var wordCount: Double = 4
    @Published var separator: SeparatorType = .hyphens
    @Published var capitalize: Bool = false
    @Published var fullWords: Bool = true

    // PIN settings
    @Published var pinLength: Double = 6

    // History
    @Published var history: [String] = []

    var strength: Int {
        PasswordStrength.calculate(generatedPassword)
    }

    private static let wordList = EFFWordList.words

    func generate() {
        isGenerating = true

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            guard let self = self else { return }

            let password: String
            switch self.generatorType {
            case .random:
                password = self.generateRandom()
            case .memorable:
                password = self.generateMemorable()
            case .pin:
                password = self.generatePIN()
            }

            self.generatedPassword = password
            self.isGenerating = false

            if !password.isEmpty {
                self.history.insert(password, at: 0)
                if self.history.count > 48 {
                    self.history.removeLast()
                }
            }
        }
    }

    private func generateRandom() -> String {
        var charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"
        if includeNumbers { charset += "23456789" }
        if includeSymbols { charset += "!@#$%^&*()_+-=" }
        return Self.secureRandomPassword(length: Int(characterCount), charset: charset)
    }

    private func generateMemorable() -> String {
        let count = Int(wordCount)
        var words: [String] = []

        for _ in 0..<count {
            var word = Self.wordList[Self.secureRandomInt(upperBound: Self.wordList.count)]
            if !fullWords {
                let end = min(word.count, 3 + Self.secureRandomInt(upperBound: 2))
                word = String(word.prefix(end))
            }
            if capitalize {
                word = word.prefix(1).uppercased() + word.dropFirst()
            }
            words.append(word)
        }

        if separator == .numbers {
            return words.enumerated().map { index, word in
                index < words.count - 1 ? word + String(Self.secureRandomInt(upperBound: 10)) : word
            }.joined()
        }

        return words.joined(separator: separator.character)
    }

    private func generatePIN() -> String {
        let length = Int(pinLength)
        return (0..<length).map { _ in String(Self.secureRandomInt(upperBound: 10)) }.joined()
    }

    // MARK: - Cryptographically Secure Random

    /// Generates a password using SecRandomCopyBytes with rejection sampling to eliminate modulo bias.
    static func secureRandomPassword(length: Int = 20, charset: String = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*()_+-=") -> String {
        let chars = Array(charset)
        guard !chars.isEmpty else { return "" }
        let charCount = chars.count
        let limit = 256 - (256 % charCount)

        var result = [Character]()
        result.reserveCapacity(length)

        while result.count < length {
            let batchSize = (length - result.count) * 2
            var bytes = [UInt8](repeating: 0, count: batchSize)
            guard SecRandomCopyBytes(kSecRandomDefault, batchSize, &bytes) == errSecSuccess else {
                fatalError("SecRandomCopyBytes failed — cannot generate secure password")
            }
            for byte in bytes where result.count < length {
                if Int(byte) < limit {
                    result.append(chars[Int(byte) % charCount])
                }
            }
        }

        return String(result)
    }

    /// Returns a cryptographically secure random integer in [0, upperBound).
    static func secureRandomInt(upperBound: Int) -> Int {
        precondition(upperBound > 0)
        if upperBound == 1 { return 0 }

        if upperBound <= 256 {
            let limit = 256 - (256 % upperBound)
            while true {
                var byte: UInt8 = 0
                guard SecRandomCopyBytes(kSecRandomDefault, 1, &byte) == errSecSuccess else {
                    fatalError("SecRandomCopyBytes failed")
                }
                if Int(byte) < limit { return Int(byte) % upperBound }
            }
        }

        let limit = UInt32.max - (UInt32.max % UInt32(upperBound))
        while true {
            var value: UInt32 = 0
            guard SecRandomCopyBytes(kSecRandomDefault, 4, &value) == errSecSuccess else {
                fatalError("SecRandomCopyBytes failed")
            }
            if value < limit { return Int(value % UInt32(upperBound)) }
        }
    }

    func copyGenerated() {
        guard !generatedPassword.isEmpty else { return }
        ClipboardService.shared.copy(generatedPassword)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            self?.copied = false
        }
    }
}
