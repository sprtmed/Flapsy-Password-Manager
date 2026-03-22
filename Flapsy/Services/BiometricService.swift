import Foundation
import LocalAuthentication

/// Handles Touch ID authentication.
final class BiometricService {
    static let shared = BiometricService()

    private init() {}

    var isBiometricAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    var biometricType: LABiometryType {
        let context = LAContext()
        var error: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return context.biometryType
    }

    /// Checks whether biometric enrollment has changed since the last authentication.
    /// Returns true if the template database was modified (e.g., new fingerprint added).
    func hasEnrollmentChanged(since domainState: Data?) -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return true
        }
        guard let currentState = context.evaluatedPolicyDomainState else { return true }
        guard let previousState = domainState else { return false }
        return currentState != previousState
    }

    func authenticate(reason: String, completion: @escaping (Bool, Error?) -> Void) {
        let context = LAContext()
        context.localizedFallbackTitle = "Enter Password"

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                completion(success, error)
            }
        }
    }
}
