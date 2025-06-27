import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

// MARK: - Biometric Manager Protocol
public protocol BiometricManagerProtocol {
    func isBiometricAvailable() -> Bool
    func authenticate(reason: String) async throws -> Bool
    func getAvailableBiometricTypes() -> [BiometricType]
    func canEvaluatePolicy() -> Bool
}

// MARK: - Biometric Types
public enum BiometricType: String, CaseIterable {
    case none = "None"
    case touchID = "Touch ID"
    case faceID = "Face ID"
    case unknown = "Unknown"
    
    public var icon: String {
        switch self {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        case .none, .unknown: return "xmark.circle"
        }
    }
}

// MARK: - Biometric Configuration
public struct BiometricConfig {
    public let enabled: Bool
    public let allowDevicePasscode: Bool
    public let fallbackTitle: String?
    public let cancelTitle: String?
    public let reason: String
    
    public init(
        enabled: Bool = true,
        allowDevicePasscode: Bool = false,
        fallbackTitle: String? = nil,
        cancelTitle: String? = nil,
        reason: String = "Authenticate to access secure data"
    ) {
        self.enabled = enabled
        self.allowDevicePasscode = allowDevicePasscode
        self.fallbackTitle = fallbackTitle
        self.cancelTitle = cancelTitle
        self.reason = reason
    }
}

// MARK: - Biometric Manager
#if canImport(LocalAuthentication)
public final class NFSBiometricManager: BiometricManagerProtocol {
    
    // MARK: - Properties
    private let configuration: BiometricConfig
    private var context: LAContext
    
    // MARK: - Initialization
    public init(configuration: BiometricConfig = BiometricConfig()) {
        self.configuration = configuration
        self.context = LAContext()
    }
    
    // MARK: - Public Methods
    
    /// Check if biometric authentication is available
    public func isBiometricAvailable() -> Bool {
        guard configuration.enabled else { return false }
        
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /// Authenticate using biometrics
    public func authenticate(reason: String = "Authenticate to access secure data") async throws -> Bool {
        guard configuration.enabled else {
            throw NFSSecurityError.biometricError("Biometric authentication is disabled")
        }
        
        // Configure context
        if let fallbackTitle = configuration.fallbackTitle {
            context.localizedFallbackTitle = fallbackTitle
        }
        
        if let cancelTitle = configuration.cancelTitle {
            context.localizedCancelTitle = cancelTitle
        }
        
        // Determine policy
        let policy: LAPolicy = configuration.allowDevicePasscode ? 
            .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
        
        // Check if policy can be evaluated
        var error: NSError?
        guard context.canEvaluatePolicy(policy, error: &error) else {
            if let error = error {
                throw NFSSecurityError.biometricError(getBiometricErrorMessage(error))
            }
            throw NFSSecurityError.biometricError("Biometric authentication not available")
        }
        
        // Perform authentication
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(policy, localizedReason: reason) { [weak self] success, error in
                if success {
                    // Reset context after successful authentication
                    self?.context.invalidate()
                    self?.context = LAContext()
                    continuation.resume(returning: true)
                } else {
                    if let error = error as? NSError {
                        continuation.resume(throwing: NFSSecurityError.biometricError(self?.getBiometricErrorMessage(error) ?? "Authentication failed"))
                    } else {
                        continuation.resume(throwing: NFSSecurityError.biometricError("Authentication failed"))
                    }
                }
            }
        }
    }
    
    /// Get available biometric types
    public func getAvailableBiometricTypes() -> [BiometricType] {
        guard configuration.enabled else { return [] }
        
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return []
        }
        
        return [getBiometricType()]
    }
    
    /// Check if policy can be evaluated
    public func canEvaluatePolicy() -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    // MARK: - Private Methods
    
    /// Get biometric type from LAContext
    private func getBiometricType() -> BiometricType {
        if #available(iOS 11.0, *) {
            switch context.biometryType {
            case .none:
                return .none
            case .touchID:
                return .touchID
            case .faceID:
                return .faceID
            case .opticID:
                return .unknown
            @unknown default:
                return .unknown
            }
        } else {
            // iOS 10 and below only support Touch ID
            return .touchID
        }
    }
    
    /// Get biometric error message from LAError
    private func getBiometricErrorMessage(_ error: NSError) -> String {
        switch error.code {
        case LAError.authenticationFailed.rawValue:
            return "There was a problem verifying your identity."
        case LAError.userCancel.rawValue:
            return "You pressed cancel."
        case LAError.userFallback.rawValue:
            return "You pressed password."
        case LAError.biometryNotAvailable.rawValue:
            return "Face ID/Touch ID is not available."
        case LAError.biometryNotEnrolled.rawValue:
            return "Face ID/Touch ID is not set up."
        case LAError.biometryLockout.rawValue:
            return "Face ID/Touch ID is locked."
        default:
            return "Face ID/Touch ID may not be configured"
        }
    }
    
    /// Get biometric type description
    private func getBiometricTypeDescription() -> String {
        switch getBiometricType() {
        case .faceID:
            return "Face ID"
        case .touchID:
            return "Touch ID"
        case .none:
            return "None"
        case .unknown:
            return "Unknown"
        }
    }
    
    /// Check if device supports biometric authentication
    private func isBiometricSupported() -> Bool {
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }
}
#else
// MARK: - Fallback Implementation for platforms without LocalAuthentication
public final class NFSBiometricManager: BiometricManagerProtocol {
    
    private let configuration: BiometricConfig
    
    public init(configuration: BiometricConfig = BiometricConfig()) {
        self.configuration = configuration
    }
    
    public func isBiometricAvailable() -> Bool {
        return false
    }
    
    public func authenticate(reason: String = "Authenticate to access secure data") async throws -> Bool {
        throw NFSSecurityError.biometricError("Biometric authentication not supported on this platform")
    }
    
    public func getAvailableBiometricTypes() -> [BiometricType] {
        return []
    }
    
    public func canEvaluatePolicy() -> Bool {
        return false
    }
}
#endif 
