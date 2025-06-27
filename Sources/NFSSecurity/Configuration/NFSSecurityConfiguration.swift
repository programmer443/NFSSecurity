import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Main Configuration
public struct NFSSecurityConfiguration {
    
    // MARK: - Encryption Configuration
    public struct EncryptionConfig {
        public let enabled: Bool
        public let defaultAlgorithm: EncryptionAlgorithm
        public let keySize: Int
        public let iterations: Int
        public let salt: String
        public let customKey: Data?
        public let customIV: Data?
        
        public init(
            enabled: Bool = true,
            defaultAlgorithm: EncryptionAlgorithm = .aes256,
            keySize: Int = 32,
            iterations: Int = 10000,
            salt: String = "NFSSecuritySalt2024",
            customKey: Data? = nil,
            customIV: Data? = nil
        ) {
            self.enabled = enabled
            self.defaultAlgorithm = defaultAlgorithm
            self.keySize = keySize
            self.iterations = iterations
            self.salt = salt
            self.customKey = customKey
            self.customIV = customIV
        }
    }
    
    // MARK: - Jailbreak Detection Configuration
    public struct JailbreakDetectionConfig {
        public let enabled: Bool
        public let checkFiles: Bool
        public let checkSystemPaths: Bool
        public let checkSandboxViolations: Bool
        public let checkDynamicLibraries: Bool
        public let checkKernelModifications: Bool
        public let checkCertificateAlterations: Bool
        public let checkCydiaSources: Bool
        public let checkBootSequence: Bool
        public let checkPersistentModifications: Bool
        public let checkRuntimeEvasion: Bool
        public let customJailbreakFiles: [String]
        
        public init(
            enabled: Bool = true,
            checkFiles: Bool = true,
            checkSystemPaths: Bool = true,
            checkSandboxViolations: Bool = true,
            checkDynamicLibraries: Bool = true,
            checkKernelModifications: Bool = true,
            checkCertificateAlterations: Bool = true,
            checkCydiaSources: Bool = true,
            checkBootSequence: Bool = true,
            checkPersistentModifications: Bool = true,
            checkRuntimeEvasion: Bool = true,
            customJailbreakFiles: [String] = []
        ) {
            self.enabled = enabled
            self.checkFiles = checkFiles
            self.checkSystemPaths = checkSystemPaths
            self.checkSandboxViolations = checkSandboxViolations
            self.checkDynamicLibraries = checkDynamicLibraries
            self.checkKernelModifications = checkKernelModifications
            self.checkCertificateAlterations = checkCertificateAlterations
            self.checkCydiaSources = checkCydiaSources
            self.checkBootSequence = checkBootSequence
            self.checkPersistentModifications = checkPersistentModifications
            self.checkRuntimeEvasion = checkRuntimeEvasion
            self.customJailbreakFiles = customJailbreakFiles
        }
    }
    
    // MARK: - Debugger Detection Configuration
    public struct DebuggerDetectionConfig {
        public let enabled: Bool
        public let checkPTrace: Bool
        public let checkSysctl: Bool
        public let checkParentProcess: Bool
        public let checkEnvironmentVariables: Bool
        public let checkBreakpoints: Bool
        public let checkDebuggerFlags: Bool
        
        public init(
            enabled: Bool = true,
            checkPTrace: Bool = true,
            checkSysctl: Bool = true,
            checkParentProcess: Bool = true,
            checkEnvironmentVariables: Bool = true,
            checkBreakpoints: Bool = true,
            checkDebuggerFlags: Bool = true
        ) {
            self.enabled = enabled
            self.checkPTrace = checkPTrace
            self.checkSysctl = checkSysctl
            self.checkParentProcess = checkParentProcess
            self.checkEnvironmentVariables = checkEnvironmentVariables
            self.checkBreakpoints = checkBreakpoints
            self.checkDebuggerFlags = checkDebuggerFlags
        }
    }
    
    // MARK: - Simulator Detection Configuration
    public struct SimulatorDetectionConfig {
        public let enabled: Bool
        public let checkDeviceModel: Bool
        public let checkEnvironmentVariables: Bool
        public let checkSystemPaths: Bool
        public let checkHardwareFeatures: Bool
        
        public init(
            enabled: Bool = true,
            checkDeviceModel: Bool = true,
            checkEnvironmentVariables: Bool = true,
            checkSystemPaths: Bool = true,
            checkHardwareFeatures: Bool = true
        ) {
            self.enabled = enabled
            self.checkDeviceModel = checkDeviceModel
            self.checkEnvironmentVariables = checkEnvironmentVariables
            self.checkSystemPaths = checkSystemPaths
            self.checkHardwareFeatures = checkHardwareFeatures
        }
    }
    
    // MARK: - Reverse Engineering Detection Configuration
    public struct ReverseEngineeringConfig {
        public let enabled: Bool
        public let checkFishHook: Bool
        public let checkMSHookFunction: Bool
        public let checkRuntimeHooks: Bool
        public let checkFileModifications: Bool
        public let checkCodeInjection: Bool
        
        public init(
            enabled: Bool = true,
            checkFishHook: Bool = true,
            checkMSHookFunction: Bool = true,
            checkRuntimeHooks: Bool = true,
            checkFileModifications: Bool = true,
            checkCodeInjection: Bool = true
        ) {
            self.enabled = enabled
            self.checkFishHook = checkFishHook
            self.checkMSHookFunction = checkMSHookFunction
            self.checkRuntimeHooks = checkRuntimeHooks
            self.checkFileModifications = checkFileModifications
            self.checkCodeInjection = checkCodeInjection
        }
    }
    
    // MARK: - Integrity Checker Configuration
    public struct IntegrityCheckerConfig {
        public let enabled: Bool
        public let checkAppBundle: Bool
        public let checkCodeSigning: Bool
        public let checkEntitlements: Bool
        public let checkFileHashes: Bool
        public let customFileHashes: [String: String]
        
        public init(
            enabled: Bool = true,
            checkAppBundle: Bool = true,
            checkCodeSigning: Bool = true,
            checkEntitlements: Bool = true,
            checkFileHashes: Bool = true,
            customFileHashes: [String: String] = [:]
        ) {
            self.enabled = enabled
            self.checkAppBundle = checkAppBundle
            self.checkCodeSigning = checkCodeSigning
            self.checkEntitlements = checkEntitlements
            self.checkFileHashes = checkFileHashes
            self.customFileHashes = customFileHashes
        }
    }
    
    // MARK: - Screen Shield Configuration
    #if canImport(UIKit)
    public struct ScreenShieldConfig {
        public let enabled: Bool
        public let preventScreenshots: Bool
        public let preventScreenRecording: Bool
        public let preventAirPlay: Bool
        public let blurOnBackground: Bool
        public let customBlurStyle: UIBlurEffect.Style
        
        public init(
            enabled: Bool = true,
            preventScreenshots: Bool = true,
            preventScreenRecording: Bool = true,
            preventAirPlay: Bool = true,
            blurOnBackground: Bool = true,
            customBlurStyle: UIBlurEffect.Style = .systemMaterial
        ) {
            self.enabled = enabled
            self.preventScreenshots = preventScreenshots
            self.preventScreenRecording = preventScreenRecording
            self.preventAirPlay = preventAirPlay
            self.blurOnBackground = blurOnBackground
            self.customBlurStyle = customBlurStyle
        }
    }
    #endif
    
    // MARK: - Hashing Configuration
    public struct HashingConfig {
        public let enabled: Bool
        public let defaultAlgorithm: HashingAlgorithm
        public let salt: String?
        
        public init(
            enabled: Bool = true,
            defaultAlgorithm: HashingAlgorithm = .sha256,
            salt: String? = nil
        ) {
            self.enabled = enabled
            self.defaultAlgorithm = defaultAlgorithm
            self.salt = salt
        }
    }
    
    // MARK: - Proxy Detection Configuration
    public struct ProxyDetectionConfig {
        public let enabled: Bool
        public let checkSystemProxy: Bool
        public let checkNetworkProxy: Bool
        public let checkVPN: Bool
        
        public init(
            enabled: Bool = true,
            checkSystemProxy: Bool = true,
            checkNetworkProxy: Bool = true,
            checkVPN: Bool = true
        ) {
            self.enabled = enabled
            self.checkSystemProxy = checkSystemProxy
            self.checkNetworkProxy = checkNetworkProxy
            self.checkVPN = checkVPN
        }
    }
    
    // MARK: - General Configuration
    public let encryption: EncryptionConfig
    public let jailbreakDetection: JailbreakDetectionConfig
    public let debuggerDetection: DebuggerDetectionConfig
    public let simulatorDetection: SimulatorDetectionConfig
    public let reverseEngineeringDetection: ReverseEngineeringConfig
    public let integrityChecker: IntegrityCheckerConfig
    public let screenShield: ScreenShieldConfig
    public let hashing: HashingConfig
    public let proxyDetection: ProxyDetectionConfig
    
    public let enableLogging: Bool
    public let enableErrorReporting: Bool
    public let customErrorHandler: ((NFSSecurityError) -> Void)?
    
    public init(
        encryption: EncryptionConfig = EncryptionConfig(),
        jailbreakDetection: JailbreakDetectionConfig = JailbreakDetectionConfig(),
        debuggerDetection: DebuggerDetectionConfig = DebuggerDetectionConfig(),
        simulatorDetection: SimulatorDetectionConfig = SimulatorDetectionConfig(),
        reverseEngineeringDetection: ReverseEngineeringConfig = ReverseEngineeringConfig(),
        integrityChecker: IntegrityCheckerConfig = IntegrityCheckerConfig(),
        screenShield: ScreenShieldConfig = ScreenShieldConfig(),
        hashing: HashingConfig = HashingConfig(),
        proxyDetection: ProxyDetectionConfig = ProxyDetectionConfig(),
        enableLogging: Bool = true,
        enableErrorReporting: Bool = true,
        customErrorHandler: ((NFSSecurityError) -> Void)? = nil
    ) {
        self.encryption = encryption
        self.jailbreakDetection = jailbreakDetection
        self.debuggerDetection = debuggerDetection
        self.simulatorDetection = simulatorDetection
        self.reverseEngineeringDetection = reverseEngineeringDetection
        self.integrityChecker = integrityChecker
        self.screenShield = screenShield
        self.hashing = hashing
        self.proxyDetection = proxyDetection
        self.enableLogging = enableLogging
        self.enableErrorReporting = enableErrorReporting
        self.customErrorHandler = customErrorHandler
    }
}

// MARK: - Supporting Enums
public enum EncryptionAlgorithm: String, CaseIterable {
    case aes128 = "AES-128"
    case aes256 = "AES-256"
    case chaCha20 = "ChaCha20"
    case sha256 = "SHA-256"
    case sha512 = "SHA-512"
}

public enum HashingAlgorithm: String, CaseIterable {
    case md5 = "MD5"
    case sha1 = "SHA-1"
    case sha256 = "SHA-256"
    case sha512 = "SHA-512"
    case hmacSha256 = "HMAC-SHA256"
    case hmacSha512 = "HMAC-SHA512"
}

public enum NFSSecurityError: Error, LocalizedError {
    case encryptionFailed(String)
    case decryptionFailed(String)
    case hashingFailed(String)
    case jailbreakDetected
    case debuggerDetected
    case simulatorDetected
    case reverseEngineeringDetected
    case integrityCheckFailed(String)
    case configurationError(String)
    case unsupportedAlgorithm(String)
    case invalidKeySize
    case invalidData
    case keychainError(String)
    case randomGenerationFailed(String)
    case biometricError(String)
    case networkSecurityError(String)
    case integrityError(String)
    case certificatePinningFailed(String)
    case timeManipulationDetected
    case deviceCompromised(String)
    
    public var errorDescription: String? {
        switch self {
        case .encryptionFailed(let message):
            return "❌ Encryption failed: \(message)"
        case .decryptionFailed(let message):
            return "❌ Decryption failed: \(message)"
        case .hashingFailed(let message):
            return "❌ Hashing failed: \(message)"
        case .jailbreakDetected:
            return "⚠️ Jailbreak detected on device"
        case .debuggerDetected:
            return "⚠️ Debugger detected"
        case .simulatorDetected:
            return "⚠️ Simulator detected"
        case .reverseEngineeringDetected:
            return "⚠️ Reverse engineering tools detected"
        case .integrityCheckFailed(let message):
            return "❌ Integrity check failed: \(message)"
        case .configurationError(let message):
            return "❌ Configuration error: \(message)"
        case .unsupportedAlgorithm(let algorithm):
            return "❌ Unsupported algorithm: \(algorithm)"
        case .invalidKeySize:
            return "❌ Invalid key size"
        case .invalidData:
            return "Invalid data provided"
        case .keychainError(let message):
            return "❌ Keychain error: \(message)"
        case .randomGenerationFailed(let message):
            return "❌ Random generation failed: \(message)"
        case .biometricError(let message):
            return "❌ Biometric authentication failed: \(message)"
        case .networkSecurityError(let message):
            return "❌ Network security error: \(message)"
        case .integrityError(let message):
            return "❌ Integrity error: \(message)"
        case .certificatePinningFailed(let message):
            return "❌ Certificate pinning failed: \(message)"
        case .timeManipulationDetected:
            return "⚠️ Device time manipulation detected"
        case .deviceCompromised(let message):
            return "⚠️ Device compromised: \(message)"
        }
    }
} 
