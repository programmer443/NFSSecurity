import Foundation
import CommonCrypto
import CryptoKit

// MARK: - Encryption Manager Protocol
public protocol EncryptionManagerProtocol {
    func encrypt(_ plainText: String, algorithm: EncryptionAlgorithm, keyData: Data?, ivData: Data?) throws -> String
    func decrypt(_ encryptedText: String, algorithm: EncryptionAlgorithm, keyData: Data?, ivData: Data?) throws -> String
    func generateKey(size: Int, salt: String, iterations: Int) throws -> Data
    func generateIV() -> Data
    func generateChaCha20Nonce() -> Data
}

// MARK: - Main Encryption Manager
public final class NFSEncryptionManager: EncryptionManagerProtocol {
    
    // MARK: - Properties
    private let configuration: NFSSecurityConfiguration.EncryptionConfig
    
    // MARK: - Initialization
    public init(configuration: NFSSecurityConfiguration.EncryptionConfig) {
        self.configuration = configuration
    }
    
    // MARK: - Public Methods
    public func encrypt(_ plainText: String, algorithm: EncryptionAlgorithm = .aes256, keyData: Data? = nil, ivData: Data? = nil) throws -> String {
        guard configuration.enabled else {
            throw NFSSecurityError.configurationError("⚠️ Encryption is disabled in configuration")
        }
        
        guard !plainText.isEmpty else {
            throw NFSSecurityError.invalidData
        }
        
        let key: Data
        if let keyData = keyData {
            key = keyData
        } else if let customKey = configuration.customKey {
            key = customKey
        } else {
            key = try generateKey(
                size: configuration.keySize,
                salt: configuration.salt,
                iterations: configuration.iterations
            )
        }
        
        let iv: Data
        if let ivData = ivData {
            iv = ivData
        } else if let customIV = configuration.customIV {
            iv = customIV
        } else {
            // Use different IV generation based on algorithm
            switch algorithm {
            case .chaCha20:
                iv = generateChaCha20Nonce()
            default:
                iv = generateIV()
            }
        }
        
        switch algorithm {
        case .aes128, .aes256:
            return try AESEncryption.encrypt(plainText, key: key, iv: iv, keySize: algorithm == .aes128 ? 16 : 32)
        case .chaCha20:
            if #available(iOS 13.0, *) {
                return try ChaCha20Encryption.encrypt(plainText, key: key, iv: iv)
            } else {
                throw NFSSecurityError.unsupportedAlgorithm("⚠️ ChaCha20 is only available on iOS 13+")
            }
        case .sha256, .sha512:
            throw NFSSecurityError.unsupportedAlgorithm("⚠️ SHA algorithms are for hashing, not encryption")
        }
    }
    
    public func decrypt(_ encryptedText: String, algorithm: EncryptionAlgorithm = .aes256, keyData: Data? = nil, ivData: Data? = nil) throws -> String {
        guard configuration.enabled else {
            throw NFSSecurityError.configurationError("⚠️ Encryption is disabled in configuration")
        }
        
        guard !encryptedText.isEmpty else {
            throw NFSSecurityError.invalidData
        }
        
        let key: Data
        if let keyData = keyData {
            key = keyData
        } else if let customKey = configuration.customKey {
            key = customKey
        } else {
            key = try generateKey(
                size: configuration.keySize,
                salt: configuration.salt,
                iterations: configuration.iterations
            )
        }
        
        switch algorithm {
        case .aes128, .aes256:
            return try AESEncryption.decrypt(encryptedText, key: key, iv: nil, keySize: algorithm == .aes128 ? 16 : 32)
        case .chaCha20:
            if #available(iOS 13.0, *) {
                return try ChaCha20Encryption.decrypt(encryptedText, key: key, iv: nil)
            } else {
                throw NFSSecurityError.unsupportedAlgorithm("⚠️  ChaCha20 is only available on iOS 13+")
            }
        case .sha256, .sha512:
            throw NFSSecurityError.unsupportedAlgorithm("⚠️  SHA algorithms are for hashing, not decryption")
        }
    }
    
    public func generateKey(size: Int, salt: String, iterations: Int) throws -> Data {
        var derivedKey = [UInt8](repeating: 0, count: size)
        let passwordData = "NFSSecurityDefaultPassword".data(using: .utf8)!
        let saltData = salt.data(using: .utf8)!
        
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
            throw NFSSecurityError.encryptionFailed("❌ Failed to generate key with status: \(status)")
        }
        
        return Data(derivedKey)
    }
    
    public func generateIV() -> Data {
        var iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        _ = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)
        return Data(iv)
    }
    
    public func generateChaCha20Nonce() -> Data {
        var nonce = [UInt8](repeating: 0, count: 12)
        _ = SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce)
        return Data(nonce)
    }
}

// MARK: - AES Encryption Implementation
private struct AESEncryption {
    
    static func encrypt(_ plainText: String, key: Data, iv: Data, keySize: Int) throws -> String {
        guard key.count == keySize else {
            throw NFSSecurityError.invalidKeySize
        }
        
        guard iv.count == kCCBlockSizeAES128 else {
            throw NFSSecurityError.invalidData
        }
        
        let plainTextData = plainText.data(using: .utf8)!
        let bufferSize = plainTextData.count + kCCBlockSizeAES128
        var encryptedBuffer = [UInt8](repeating: 0, count: bufferSize)
        var encryptedLength: size_t = 0
        
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                plainTextData.withUnsafeBytes { plainTextBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress,
                        key.count,
                        ivBytes.baseAddress,
                        plainTextBytes.baseAddress,
                        plainTextData.count,
                        &encryptedBuffer,
                        bufferSize,
                        &encryptedLength
                    )
                }
            }
        }
        
        guard status == kCCSuccess else {
            throw NFSSecurityError.encryptionFailed("❌ AES encryption failed with status: \(status)")
        }
        
        let encryptedData = Data(bytes: encryptedBuffer, count: encryptedLength)
        let combined = iv + encryptedData
        return combined.base64EncodedString()
    }
    
    static func decrypt(_ encryptedText: String, key: Data, iv: Data?, keySize: Int) throws -> String {
        guard key.count == keySize else {
            throw NFSSecurityError.invalidKeySize
        }
        
        guard let combinedData = Data(base64Encoded: encryptedText) else {
            throw NFSSecurityError.invalidData
        }
        
        guard combinedData.count > kCCBlockSizeAES128 else {
            throw NFSSecurityError.invalidData
        }
        let iv = combinedData.prefix(kCCBlockSizeAES128)
        let encryptedData = combinedData.dropFirst(kCCBlockSizeAES128)
        
        guard iv.count == kCCBlockSizeAES128 else {
            throw NFSSecurityError.invalidData
        }
        
        var decryptedBuffer = [UInt8](repeating: 0, count: encryptedData.count)
        var decryptedLength: size_t = 0
        
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                encryptedData.withUnsafeBytes { encryptedBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress,
                        key.count,
                        ivBytes.baseAddress,
                        encryptedBytes.baseAddress,
                        encryptedData.count,
                        &decryptedBuffer,
                        decryptedBuffer.count,
                        &decryptedLength
                    )
                }
            }
        }
        
        guard status == kCCSuccess else {
            throw NFSSecurityError.decryptionFailed("❌ AES decryption failed with status: \(status)")
        }
        
        let decryptedData = Data(bytes: decryptedBuffer, count: decryptedLength)
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw NFSSecurityError.decryptionFailed("❌ Failed to convert decrypted data to string")
        }
        
        return decryptedString
    }
}

// MARK: - ChaCha20 Encryption Implementation
@available(iOS 13.0, *)
private struct ChaCha20Encryption {
    
    static func encrypt(_ plainText: String, key: Data, iv: Data) throws -> String {
        guard key.count == 32 else {
            throw NFSSecurityError.invalidKeySize
        }
        
        guard iv.count == 12 else {
            throw NFSSecurityError.invalidData
        }
        
        let symmetricKey = SymmetricKey(data: key)
        let nonce = try ChaChaPoly.Nonce(data: iv)
        let plainTextData = plainText.data(using: .utf8)!
        
        let sealedBox = try ChaChaPoly.seal(plainTextData, using: symmetricKey, nonce: nonce)
        let encryptedData = sealedBox.combined
        
        // Combine nonce with encrypted data (like AES does)
        let combined = iv + encryptedData
        return combined.base64EncodedString()
    }
    
    static func decrypt(_ encryptedText: String, key: Data, iv: Data?) throws -> String {
        guard key.count == 32 else {
            throw NFSSecurityError.invalidKeySize
        }
        
        guard let combinedData = Data(base64Encoded: encryptedText) else {
            throw NFSSecurityError.invalidData
        }
        
        guard combinedData.count > 12 else {
            throw NFSSecurityError.invalidData
        }
        
        // Extract nonce and encrypted data
        let nonce = combinedData.prefix(12)
        let encryptedData = combinedData.dropFirst(12)
        
        guard nonce.count == 12 else {
            throw NFSSecurityError.invalidData
        }
        
        let symmetricKey = SymmetricKey(data: key)
        let sealedBox = try ChaChaPoly.SealedBox(combined: encryptedData)
        let decryptedData = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw NFSSecurityError.decryptionFailed("❌ Failed to convert decrypted data to string")
        }
        
        return decryptedString
    }
}
