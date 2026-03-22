import Foundation

struct FuzzyMatch {
    let score: Int
    let matchedIndices: [Int]
}

enum FuzzySearch {
    /// Pre-normalizes Unicode combining characters for consistent matching.
    /// Handles cases like é (U+00E9) vs e + ´ (U+0065 U+0301).
    private static func canonicalizeInput(_ input: String) -> String {
        input.precomposedStringWithCanonicalMapping.lowercased()
            .folding(options: [.diacriticInsensitive], locale: .current)
    }

    /// Fuzzy match `query` against `text`. Returns nil if not all query characters found.
    /// Score rewards consecutive matches and word-boundary matches.
    static func match(query: String, in text: String) -> FuzzyMatch? {
        guard !query.isEmpty else { return FuzzyMatch(score: 0, matchedIndices: []) }

        let queryChars = Array(query.lowercased())
        let textChars = Array(text.lowercased())

        var queryIdx = 0
        var matchedIndices: [Int] = []
        var score = 0
        var consecutiveMatches = 0
        var lastMatchIdx = -2

        for (textIdx, char) in textChars.enumerated() {
            guard queryIdx < queryChars.count else { break }

            if char == queryChars[queryIdx] {
                matchedIndices.append(textIdx)

                // Consecutive match bonus
                if textIdx == lastMatchIdx + 1 {
                    consecutiveMatches += 1
                    score += consecutiveMatches * 3
                } else {
                    consecutiveMatches = 1
                    score += 1
                }

                // Word boundary bonus
                if textIdx == 0 ||
                    textChars[textIdx - 1] == " " ||
                    textChars[textIdx - 1] == "." ||
                    textChars[textIdx - 1] == "/" ||
                    textChars[textIdx - 1] == "-" ||
                    textChars[textIdx - 1] == "_" ||
                    textChars[textIdx - 1] == "@" {
                    score += 5
                }

                lastMatchIdx = textIdx
                queryIdx += 1
            }
        }

        guard queryIdx == queryChars.count else { return nil }
        return FuzzyMatch(score: score, matchedIndices: matchedIndices)
    }
}
