import Foundation
import LocalAuthentication
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Security Manager Protocols
public protocol SecurityDetectionProtocol {
    func isDebuggerAttached() -> Bool
    func isJailbroken() -> Bool
    func isRunningInSimulator() -> Bool
    func isReverseEngineeringToolsDetected() -> Bool
}

public protocol SecurityOperationProtocol {
    func hash(_ data: Data, using algorithm: HashingAlgorithm) throws -> Data
    func hash(_ string: String, using algorithm: HashingAlgorithm) throws -> Data
    func verifyHash(_ data: Data, hash: Data, using algorithm: HashingAlgorithm) throws -> Bool
    func encrypt(_ data: Data, using algorithm: EncryptionAlgorithm, withKey key: String) throws -> Data
    func decrypt(_ data: Data, using algorithm: EncryptionAlgorithm, withKey key: String) throws -> Data
}

// MARK: - NFSSecurity Main Class
public final class NFSSecurity: SecurityDetectionProtocol, SecurityOperationProtocol, @unchecked Sendable {
    
    // MARK: - Singleton
    public static let shared = NFSSecurity()
    
    // MARK: - Properties
    private let biometricManager: NFSBiometricManager
    private let keychainManager: NFSKeychainManager
    private let randomGenerator: NFSRandomGenerator
    private let integrityManager: NFSIntegrityManager
    private let networkSecurityManager: NFSNetworkSecurityManager
    private let encryptionManager: NFSEncryptionManager
    private let hashingManager: NFSHashingManager
    private let screenShield: NFSScreenShield
    private let modesChecker: NFSModesChecker
    
    // MARK: - Initialization
    private init() {
        // Initialize all security managers with default configurations
        self.biometricManager = NFSBiometricManager()
        self.keychainManager = NFSKeychainManager()
        self.randomGenerator = NFSRandomGenerator()
        self.integrityManager = NFSIntegrityManager()
        self.networkSecurityManager = NFSNetworkSecurityManager()
        
        // Initialize encryption manager with default configuration
        let encryptionConfig = NFSSecurityConfiguration.EncryptionConfig()
        self.encryptionManager = NFSEncryptionManager(configuration: encryptionConfig)
        
        // Initialize hashing manager with default configuration
        let hashingConfig = NFSSecurityConfiguration.HashingConfig()
        self.hashingManager = NFSHashingManager(configuration: hashingConfig)
        
        // Initialize screen shield with default configuration
        self.screenShield = NFSScreenShield(configuration: NFSSecurityConfiguration.ScreenShieldConfig(
            enabled: true,
            preventScreenshots: true,
            preventScreenRecording: true,
            preventAirPlay: true,
            blurOnBackground: true,
            customBlurStyle: .systemUltraThinMaterialDark
        )
)
        self.modesChecker = NFSModesChecker()
    }
    
    // MARK: - Public Methods
    
    /// Perform comprehensive security check
    @MainActor
    public func performSecurityCheck() -> SecurityCheckResult {
        var issues: [String] = []
        var isSecure = true
        
        // Check debugger
        if isDebuggerAttached() {
            issues.append("Debugger detected")
            isSecure = false
        }
        
        // Check jailbreak
        if isJailbroken() {
            issues.append("Jailbreak detected")
            isSecure = false
        }
        
        // Check simulator
        if isRunningInSimulator() {
            issues.append("Running in simulator")
            isSecure = false
        }
        
        // Check reverse engineering tools
        if isReverseEngineeringToolsDetected() {
            issues.append("Reverse engineering tools detected")
            isSecure = false
        }
        
        // Check app integrity
        if !integrityManager.verifyAppIntegrity() {
            issues.append("App integrity check failed")
            isSecure = false
        }
        
        // Check network security
        let networkResult = networkSecurityManager.checkNetworkSecurity()
        if !networkResult.isSecure {
            issues.append(contentsOf: networkResult.issues)
            isSecure = false
        }
        
        return SecurityCheckResult(
            isSecure: isSecure,
            issues: issues
        )
    }
    
    // MARK: - Security Detection Implementation
    
    /// Check if debugger is attached
    public func isDebuggerAttached() -> Bool {
        return NFSDebuggerDetection.isDebuggerAttached()
    }
    
    /// Check if device is jailbroken
    public func isJailbroken() -> Bool {
        return NFSJailbreakDetection.isJailbroken()
    }
    
    /// Check if running in simulator
    public func isRunningInSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
    /// Check for reverse engineering tools
    public func isReverseEngineeringToolsDetected() -> Bool {
        // Check for common reverse engineering tools
        let toolPaths = [
            "/usr/bin/gdb",
            "/usr/bin/cycript",
            "/usr/bin/cynject",
            "/usr/bin/class-dump",
            "/usr/bin/class-dump-z",
            "/usr/bin/otool",
            "/usr/bin/lipo"
        ]
        
        for path in toolPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    // MARK: - Security Operations Implementation
    
    /// Hash data
    public func hash(_ data: Data, using algorithm: HashingAlgorithm) throws -> Data {
        let hashString = try hashingManager.hash(data, algorithm: algorithm)
        return Data(hashString.utf8)
    }
    
    /// Hash string
    public func hash(_ string: String, using algorithm: HashingAlgorithm) throws -> Data {
        let hashString = try hashingManager.hash(string, algorithm: algorithm)
        return Data(hashString.utf8)
    }
    
    /// Verify hash
    public func verifyHash(_ data: Data, hash: Data, using algorithm: HashingAlgorithm) throws -> Bool {
        let hashString = String(data: hash, encoding: .utf8) ?? ""
        return try hashingManager.verify(data, hash: hashString, algorithm: algorithm)
    }
    
    /// Encrypt data
    public func encrypt(_ data: Data, using algorithm: EncryptionAlgorithm, withKey key: String) throws -> Data {
        guard let inputString = String(data: data, encoding: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        
        // Create key data from user's key with proper padding/truncation
        let keyData: Data
        switch algorithm {
        case .aes128:
            // Pad or truncate to 16 bytes
            let keyBytes = Array(key.utf8)
            if keyBytes.count >= 16 {
                keyData = Data(keyBytes.prefix(16))
            } else {
                keyData = Data(keyBytes + Array(repeating: 0, count: 16 - keyBytes.count))
            }
        case .aes256:
            // Pad or truncate to 32 bytes
            let keyBytes = Array(key.utf8)
            if keyBytes.count >= 32 {
                keyData = Data(keyBytes.prefix(32))
            } else {
                keyData = Data(keyBytes + Array(repeating: 0, count: 32 - keyBytes.count))
            }
        case .chaCha20:
            // Pad or truncate to 32 bytes
            let keyBytes = Array(key.utf8)
            if keyBytes.count >= 32 {
                keyData = Data(keyBytes.prefix(32))
            } else {
                keyData = Data(keyBytes + Array(repeating: 0, count: 32 - keyBytes.count))
            }
        case .sha256, .sha512:
            throw NFSSecurityError.unsupportedAlgorithm("SHA algorithms are for hashing, not encryption")
        }
        
        let encryptedString = try encryptionManager.encrypt(inputString, algorithm: algorithm, keyData: keyData, ivData: nil)
        return Data(encryptedString.utf8)
    }
    
    /// Decrypt data
    public func decrypt(_ data: Data, using algorithm: EncryptionAlgorithm, withKey key: String) throws -> Data {
        guard let encryptedString = String(data: data, encoding: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        
        // Create key data from user's key with proper padding/truncation
        let keyData: Data
        switch algorithm {
        case .aes128:
            // Pad or truncate to 16 bytes
            let keyBytes = Array(key.utf8)
            if keyBytes.count >= 16 {
                keyData = Data(keyBytes.prefix(16))
            } else {
                keyData = Data(keyBytes + Array(repeating: 0, count: 16 - keyBytes.count))
            }
        case .aes256:
            // Pad or truncate to 32 bytes
            let keyBytes = Array(key.utf8)
            if keyBytes.count >= 32 {
                keyData = Data(keyBytes.prefix(32))
            } else {
                keyData = Data(keyBytes + Array(repeating: 0, count: 32 - keyBytes.count))
            }
        case .chaCha20:
            // Pad or truncate to 32 bytes
            let keyBytes = Array(key.utf8)
            if keyBytes.count >= 32 {
                keyData = Data(keyBytes.prefix(32))
            } else {
                keyData = Data(keyBytes + Array(repeating: 0, count: 32 - keyBytes.count))
            }
        case .sha256, .sha512:
            throw NFSSecurityError.unsupportedAlgorithm("SHA algorithms are for hashing, not decryption")
        }
        
        let decryptedString = try encryptionManager.decrypt(encryptedString, algorithm: algorithm, keyData: keyData, ivData: nil)
        guard let decryptedData = decryptedString.data(using: .utf8) else {
            throw NFSSecurityError.decryptionFailed("Failed to convert decrypted string to data")
        }
        return decryptedData
    }
    
    // MARK: - Biometric Authentication
    
    /// Check if biometric authentication is available
    @MainActor
    public func isBiometricAvailable() -> Bool {
        return biometricManager.isBiometricAvailable()
    }
    
    /// Authenticate using biometrics
    @MainActor
    public func authenticateWithBiometrics(reason: String = "Authenticate to access secure data") async throws -> Bool {
        return try await biometricManager.authenticate(reason: reason)
    }
    
    /// Get available biometric types
    @MainActor
    public func getAvailableBiometricTypes() -> [BiometricType] {
        return biometricManager.getAvailableBiometricTypes()
    }
    
    // MARK: - Keychain Operations
    
    /// Store data in keychain
    public func storeInKeychain(_ data: Data, forKey key: String, accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) throws {
        try keychainManager.store(data, forKey: key, accessibility: accessibility)
    }
    
    /// Retrieve data from keychain
    public func retrieveFromKeychain(forKey key: String) throws -> Data {
        return try keychainManager.retrieve(forKey: key)
    }
    
    /// Delete data from keychain
    public func deleteFromKeychain(forKey key: String) throws {
        try keychainManager.delete(forKey: key)
    }
    
    /// Store string in keychain
    public func storeStringInKeychain(_ string: String, forKey key: String, accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) throws {
        try keychainManager.storeString(string, forKey: key, accessibility: accessibility)
    }
    
    /// Retrieve string from keychain
    public func retrieveStringFromKeychain(forKey key: String) throws -> String {
        return try keychainManager.retrieveString(forKey: key)
    }
    
    // MARK: - Random Generation
    
    /// Generate secure random data
    public func generateRandomData(length: Int) throws -> Data {
        return try randomGenerator.generateData(length: length)
    }
    
    /// Generate secure random string
    public func generateRandomString(length: Int, characterSet: RandomCharacterSet = .alphanumeric) throws -> String {
        return try randomGenerator.generateString(length: length, characterSet: characterSet)
    }
    
    /// Generate secure password
    public func generateSecurePassword(length: Int = 16) throws -> String {
        return try randomGenerator.generatePassword(length: length)
    }
    
    /// Generate UUID
    public func generateUUID() -> UUID {
        return randomGenerator.generateUUID()
    }
    
    // MARK: - Screen Shield
    
    /// Enable screen shield
    @MainActor
    public func enableScreenShield() {
        screenShield.enable()
    }
    
    /// Disable screen shield
    @MainActor
    public func disableScreenShield() {
        screenShield.disable()
    }
    
    // MARK: - Network Security
    
    /// Check network security
    public func checkNetworkSecurity() -> NetworkSecurityResult {
        return networkSecurityManager.checkNetworkSecurity()
    }
    
    /// Detect proxy
    public func detectProxy() -> Bool {
        return networkSecurityManager.detectProxy()
    }
    
    // MARK: - Integrity
    
    /// Verify app integrity
    public func verifyAppIntegrity() -> Bool {
        return integrityManager.verifyAppIntegrity()
    }
    
    /// Perform comprehensive integrity check
    public func performIntegrityCheck() -> IntegrityResult {
        return integrityManager.performIntegrityCheck()
    }
}

// MARK: - Security Check Result
public struct SecurityCheckResult {
    public let isSecure: Bool
    public let issues: [String]
    
    public init(isSecure: Bool, issues: [String]) {
        self.isSecure = isSecure
        self.issues = issues
    }
}
