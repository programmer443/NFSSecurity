import Foundation
import Security

// MARK: - Random Generator Protocol
public protocol RandomGeneratorProtocol {
    func generateData(length: Int) throws -> Data
    func generateString(length: Int, characterSet: String) throws -> String
    func generateBytes(length: Int) throws -> [UInt8]
    func generateUUID() -> UUID
    func generateSecureToken() throws -> String
}

// MARK: - Random Configuration
public struct RandomConfig {
    public let defaultLength: Int
    public let defaultCharacterSet: String
    public let useSecureRandom: Bool
    
    public init(
        defaultLength: Int = 32,
        defaultCharacterSet: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        useSecureRandom: Bool = true
    ) {
        self.defaultLength = defaultLength
        self.defaultCharacterSet = defaultCharacterSet
        self.useSecureRandom = useSecureRandom
    }
}

// MARK: - Character Sets
public enum RandomCharacterSet: String, CaseIterable {
    case alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    case numeric = "0123456789"
    case alphabetic = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    case uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    case lowercase = "abcdefghijklmnopqrstuvwxyz"
    case hex = "0123456789ABCDEF"
    case base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    case urlSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    
    public var characters: String {
        return rawValue
    }
}

// MARK: - Random Generator
public final class NFSRandomGenerator: RandomGeneratorProtocol {
    
    // MARK: - Properties
    private let configuration: RandomConfig
    
    // MARK: - Initialization
    public init(configuration: RandomConfig = RandomConfig()) {
        self.configuration = configuration
    }
    
    // MARK: - Public Methods
    
    /// Generate secure random data
    public func generateData(length: Int) throws -> Data {
        guard length > 0 else {
            throw NFSSecurityError.randomGenerationFailed("Length must be greater than 0")
        }
        
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        
        guard status == errSecSuccess else {
            throw NFSSecurityError.randomGenerationFailed("Failed to generate random data: \(status)")
        }
        
        return Data(bytes)
    }
    
    /// Generate secure random string
    public func generateString(length: Int, characterSet: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") throws -> String {
        guard length > 0 else {
            throw NFSSecurityError.randomGenerationFailed("Length must be greater than 0")
        }
        
        guard !characterSet.isEmpty else {
            throw NFSSecurityError.randomGenerationFailed("Character set cannot be empty")
        }
        
        let data = try generateData(length: length)
        let characters = Array(characterSet)
        
        return String(data.map { characters[Int($0) % characters.count] })
    }
    
    /// Generate secure random bytes
    public func generateBytes(length: Int) throws -> [UInt8] {
        let data = try generateData(length: length)
        return Array(data)
    }
    
    /// Generate UUID
    public func generateUUID() -> UUID {
        return UUID()
    }
    
    /// Generate secure token (UUID-based)
    public func generateSecureToken() throws -> String {
        return generateUUID().uuidString.replacingOccurrences(of: "-", with: "")
    }
    
    // MARK: - Convenience Methods
    
    /// Generate random data with default length
    public func generateData() throws -> Data {
        return try generateData(length: configuration.defaultLength)
    }
    
    /// Generate random string with default length and character set
    public func generateString() throws -> String {
        return try generateString(length: configuration.defaultLength, characterSet: configuration.defaultCharacterSet)
    }
    
    /// Generate random string with predefined character set
    public func generateString(length: Int, characterSet: RandomCharacterSet) throws -> String {
        return try generateString(length: length, characterSet: characterSet.characters)
    }
    
    /// Generate random password
    public func generatePassword(length: Int = 16) throws -> String {
        // Include at least one character from each category
        let uppercase = RandomCharacterSet.uppercase.characters
        let lowercase = RandomCharacterSet.lowercase.characters
        let numbers = RandomCharacterSet.numeric.characters
        let special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        var password = ""
        
        // Ensure at least one character from each category
        password += String(uppercase.randomElement()!)
        password += String(lowercase.randomElement()!)
        password += String(numbers.randomElement()!)
        password += String(special.randomElement()!)
        
        // Fill the rest with random characters
        let remainingLength = length - 4
        let allCharacters = uppercase + lowercase + numbers + special
        password += try generateString(length: remainingLength, characterSet: allCharacters)
        
        // Shuffle the password
        return String(password.shuffled())
    }
    
    /// Generate random hex string
    public func generateHexString(length: Int) throws -> String {
        return try generateString(length: length, characterSet: RandomCharacterSet.hex)
    }
    
    /// Generate random base64 string
    public func generateBase64String(length: Int) throws -> String {
        return try generateString(length: length, characterSet: RandomCharacterSet.base64)
    }
    
    /// Generate random URL-safe string
    public func generateURLSafeString(length: Int) throws -> String {
        return try generateString(length: length, characterSet: RandomCharacterSet.urlSafe)
    }
    
    /// Generate random number in range
    public func generateNumber(in range: ClosedRange<Int>) throws -> Int {
        let data = try generateData(length: 8)
        let randomValue = data.withUnsafeBytes { bytes in
            bytes.load(as: UInt64.self)
        }
        let normalizedValue = Double(randomValue) / Double(UInt64.max)
        return Int(Double(range.lowerBound) + normalizedValue * Double(range.upperBound - range.lowerBound))
    }
    
    /// Generate random boolean
    public func generateBoolean() throws -> Bool {
        let data = try generateData(length: 1)
        return data.first! % 2 == 0
    }
    
    // MARK: - Private Methods
    
    /// Validate length parameter
    private func validateLength(_ length: Int) throws {
        guard length > 0 else {
            throw NFSSecurityError.randomGenerationFailed("Length must be greater than 0")
        }
        
        guard length <= 1024 * 1024 else { // 1MB limit
            throw NFSSecurityError.randomGenerationFailed("Length too large (max 1MB)")
        }
    }
    
    /// Get random status description
    private func getRandomStatusDescription(_ status: OSStatus) -> String {
        switch status {
        case errSecSuccess:
            return "Success"
        case errSecParam:
            return "Invalid parameter"
        case errSecAllocate:
            return "Memory allocation failed"
        case errSecNotAvailable:
            return "Random number generator not available"
        default:
            return "Unknown error: \(status)"
        }
    }
} 