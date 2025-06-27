import Foundation
import CommonCrypto
import CryptoKit

// MARK: - Hashing Manager Protocol
public protocol HashingManagerProtocol {
    func hash(_ data: Data, algorithm: HashingAlgorithm, salt: String?) throws -> String
    func hash(_ string: String, algorithm: HashingAlgorithm, salt: String?) throws -> String
    func verify(_ data: Data, hash: String, algorithm: HashingAlgorithm, salt: String?) throws -> Bool
    func verify(_ string: String, hash: String, algorithm: HashingAlgorithm, salt: String?) throws -> Bool
}

// MARK: - Main Hashing Manager
public final class NFSHashingManager: HashingManagerProtocol {
    
    // MARK: - Properties
    private let configuration: NFSSecurityConfiguration.HashingConfig
    
    // MARK: - Initialization
    public init(configuration: NFSSecurityConfiguration.HashingConfig) {
        self.configuration = configuration
    }
    
    // MARK: - Public Methods
    public func hash(_ data: Data, algorithm: HashingAlgorithm = .sha256, salt: String? = nil) throws -> String {
        guard configuration.enabled else {
            throw NFSSecurityError.configurationError("⚠️ Hashing is disabled in configuration")
        }
        
        let finalSalt = salt ?? configuration.salt ?? ""
        let saltedData = finalSalt.isEmpty ? data : (finalSalt.data(using: .utf8)! + data)
        
        switch algorithm {
        case .md5:
            return try MD5Hasher.hash(saltedData)
        case .sha1:
            return try SHA1Hasher.hash(saltedData)
        case .sha256:
            return try SHA256Hasher.hash(saltedData)
        case .sha512:
            return try SHA512Hasher.hash(saltedData)
        case .hmacSha256:
            return try HMACSHA256Hasher.hash(saltedData, key: finalSalt)
        case .hmacSha512:
            return try HMACSHA512Hasher.hash(saltedData, key: finalSalt)
        }
    }
    
    public func hash(_ string: String, algorithm: HashingAlgorithm = .sha256, salt: String? = nil) throws -> String {
        guard let data = string.data(using: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        return try hash(data, algorithm: algorithm, salt: salt)
    }
    
    public func verify(_ data: Data, hash: String, algorithm: HashingAlgorithm = .sha256, salt: String? = nil) throws -> Bool {
        let computedHash = try self.hash(data, algorithm: algorithm, salt: salt)
        return computedHash.lowercased() == hash.lowercased()
    }
    
    public func verify(_ string: String, hash: String, algorithm: HashingAlgorithm = .sha256, salt: String? = nil) throws -> Bool {
        guard let data = string.data(using: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        let computedHash = try self.hash(data, algorithm: algorithm, salt: salt)
        return computedHash.lowercased() == hash.lowercased()
    }
}

// MARK: - MD5 Hasher
private struct MD5Hasher {
    static func hash(_ data: Data) throws -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        
        data.withUnsafeBytes { bytes in
            CC_MD5(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
}

// MARK: - SHA1 Hasher
private struct SHA1Hasher {
    static func hash(_ data: Data) throws -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        
        data.withUnsafeBytes { bytes in
            CC_SHA1(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
}

// MARK: - SHA256 Hasher
private struct SHA256Hasher {
    static func hash(_ data: Data) throws -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        data.withUnsafeBytes { bytes in
            CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
}

// MARK: - SHA512 Hasher
private struct SHA512Hasher {
    static func hash(_ data: Data) throws -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        
        data.withUnsafeBytes { bytes in
            CC_SHA512(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
}

// MARK: - HMAC-SHA256 Hasher
private struct HMACSHA256Hasher {
    static func hash(_ data: Data, key: String) throws -> String {
        guard let keyData = key.data(using: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        keyData.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA256),
                    keyBytes.baseAddress,
                    keyData.count,
                    dataBytes.baseAddress,
                    data.count,
                    &digest
                )
            }
        }
        
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
}

// MARK: - HMAC-SHA512 Hasher
private struct HMACSHA512Hasher {
    static func hash(_ data: Data, key: String) throws -> String {
        guard let keyData = key.data(using: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        
        keyData.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA512),
                    keyBytes.baseAddress,
                    keyData.count,
                    dataBytes.baseAddress,
                    data.count,
                    &digest
                )
            }
        }
        
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
}

// MARK: - CryptoKit Extensions for Modern Hashing
extension NFSHashingManager {
    
    /// Modern hashing using CryptoKit (iOS 13+)
    public func modernHash(_ data: Data, algorithm: HashingAlgorithm) throws -> String {
        switch algorithm {
        case .sha256:
            let hash = SHA256.hash(data: data)
            return hash.compactMap { String(format: "%02x", $0) }.joined()
        case .sha512:
            let hash = SHA512.hash(data: data)
            return hash.compactMap { String(format: "%02x", $0) }.joined()
        case .hmacSha256:
            let key = SymmetricKey(size: .bits256)
            let signature = HMAC<SHA256>.authenticationCode(for: data, using: key)
            return Data(signature).map { String(format: "%02x", $0) }.joined()
        case .hmacSha512:
            let key = SymmetricKey(size: .init(bitCount: 512))
            let signature = HMAC<SHA512>.authenticationCode(for: data, using: key)
            return Data(signature).map { String(format: "%02x", $0) }.joined()
        default:
            throw NFSSecurityError.unsupportedAlgorithm("⚠️ CryptoKit doesn't support \(algorithm.rawValue)")
        }
    }
    
    /// Generate a secure random salt
    public func generateSalt(length: Int = 32) -> String {
        var bytes = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        return Data(bytes).base64EncodedString()
    }
    
    /// Hash with salt using PBKDF2
    public func hashWithPBKDF2(_ password: String, salt: String, iterations: Int = 10000, keyLength: Int = 32) throws -> String {
        guard let passwordData = password.data(using: .utf8),
              let saltData = salt.data(using: .utf8) else {
            throw NFSSecurityError.invalidData
        }
        
        var derivedKey = [UInt8](repeating: 0, count: keyLength)
        
        let status = saltData.withUnsafeBytes { saltBytes in
            passwordData.withUnsafeBytes { passwordBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordData.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    saltData.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    &derivedKey,
                    derivedKey.count
                )
            }
        }
        
        guard status == kCCSuccess else {
            throw NFSSecurityError.hashingFailed("❌ PBKDF2 failed with status: \(status)")
        }
        
        return Data(derivedKey).base64EncodedString()
    }
}
