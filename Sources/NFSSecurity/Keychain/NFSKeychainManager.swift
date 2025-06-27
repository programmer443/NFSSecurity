import Foundation
import Security

// MARK: - Keychain Manager Protocol
public protocol KeychainManagerProtocol {
    func store(_ data: Data, forKey key: String, accessibility: CFString) throws
    func retrieve(forKey key: String) throws -> Data
    func delete(forKey key: String) throws
    func update(_ data: Data, forKey key: String) throws
    func exists(forKey key: String) -> Bool
    func clearAll() throws
}

// MARK: - Keychain Configuration
public struct KeychainConfig {
    public let service: String
    public let accessGroup: String?
    public let defaultAccessibility: CFString
    public let synchronizable: Bool
    
    public init(
        service: String = "NFSSecurity",
        accessGroup: String? = nil,
        defaultAccessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        synchronizable: Bool = false
    ) {
        self.service = service
        self.accessGroup = accessGroup
        self.defaultAccessibility = defaultAccessibility
        self.synchronizable = synchronizable
    }
}

// MARK: - Keychain Accessibility Options
public enum KeychainAccessibility: String, CaseIterable {
    case whenUnlocked = "When Unlocked"
    case whenUnlockedThisDeviceOnly = "When Unlocked (This Device Only)"
    case afterFirstUnlock = "After First Unlock"
    case afterFirstUnlockThisDeviceOnly = "After First Unlock (This Device Only)"
    case always = "Always"
    case alwaysThisDeviceOnly = "Always (This Device Only)"
    case whenPasscodeSetThisDeviceOnly = "When Passcode Set (This Device Only)"
    
    public var cfValue: CFString {
        switch self {
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .always:
            return kSecAttrAccessibleAlways
        case .alwaysThisDeviceOnly:
            return kSecAttrAccessibleAlwaysThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }
}

// MARK: - Keychain Manager
public final class NFSKeychainManager: KeychainManagerProtocol {
    
    // MARK: - Properties
    private let configuration: KeychainConfig
    
    // MARK: - Initialization
    public init(configuration: KeychainConfig = KeychainConfig()) {
        self.configuration = configuration
    }
    
    // MARK: - Public Methods
    
    /// Store data securely in Keychain
    public func store(_ data: Data, forKey key: String, accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility,
            kSecAttrSynchronizable as String: configuration.synchronizable
        ]
        
        // Add access group if specified
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status == errSecDuplicateItem {
            // Item already exists, update it
            try update(data, forKey: key)
        } else if status != errSecSuccess {
            throw NFSSecurityError.keychainError("Failed to add keychain item: \(status)")
        }
    }
    
    /// Retrieve data from Keychain
    public func retrieve(forKey key: String) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: configuration.synchronizable
        ]
        
        // Add access group if specified
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw NFSSecurityError.keychainError("Failed to retrieve keychain item: \(status)")
        }
        
        guard let data = result as? Data else {
            throw NFSSecurityError.keychainError("Invalid data format")
        }
        
        return data
    }
    
    /// Delete data from Keychain
    public func delete(forKey key: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: configuration.synchronizable
        ]
        
        // Add access group if specified
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NFSSecurityError.keychainError("Failed to delete keychain item: \(status)")
        }
    }
    
    /// Update existing data in Keychain
    public func update(_ data: Data, forKey key: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: configuration.synchronizable
        ]
        
        // Add access group if specified
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let attributes: [String: Any] = [
            kSecValueData as String: data
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        
        guard status == errSecSuccess else {
            throw NFSSecurityError.keychainError("Failed to update keychain item: \(status)")
        }
    }
    
    /// Check if key exists in Keychain
    public func exists(forKey key: String) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: configuration.synchronizable
        ]
        
        // Add access group if specified
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /// Clear all items for this service
    public func clearAll() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service,
            kSecAttrSynchronizable as String: configuration.synchronizable
        ]
        
        // Add access group if specified
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NFSSecurityError.keychainError("Failed to clear keychain items: \(status)")
        }
    }
    
    // MARK: - Convenience Methods
    
    /// Store string in Keychain
    public func storeString(_ string: String, forKey key: String, accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) throws {
        guard let data = string.data(using: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        try store(data, forKey: key, accessibility: accessibility)
    }
    
    /// Retrieve string from Keychain
    public func retrieveString(forKey key: String) throws -> String {
        let data = try retrieve(forKey: key)
        guard let string = String(data: data, encoding: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        return string
    }
    
    /// Store dictionary in Keychain
    public func storeDictionary(_ dictionary: [String: Any], forKey key: String, accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) throws {
        let data = try JSONSerialization.data(withJSONObject: dictionary)
        try store(data, forKey: key, accessibility: accessibility)
    }
    
    /// Retrieve dictionary from Keychain
    public func retrieveDictionary(forKey key: String) throws -> [String: Any] {
        let data = try retrieve(forKey: key)
        guard let dictionary = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NFSSecurityError.invalidData
        }
        return dictionary
    }
    
    // MARK: - Private Methods
    
    /// Get keychain status description
    private func getKeychainStatusDescription(_ status: OSStatus) -> String {
        switch status {
        case errSecSuccess:
            return "Success"
        case errSecDuplicateItem:
            return "Item already exists"
        case errSecItemNotFound:
            return "Item not found"
        case errSecParam:
            return "Invalid parameter"
        case errSecAllocate:
            return "Memory allocation failed"
        case errSecNotAvailable:
            return "Not available"
        case errSecAuthFailed:
            return "Authentication failed"
        case errSecDecode:
            return "Decode failed"
        case errSecUnimplemented:
            return "Unimplemented"
        default:
            return "Unknown error: \(status)"
        }
    }
} 