import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Data Extensions
public extension Data {
    
    /// Convert Data to hex string
    func toHexString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    /// Initialize Data from hex string
    init?(hex: String) {
        let len = hex.count / 2
        var data = Data(capacity: len)
        var i = hex.startIndex
        for _ in 0..<len {
            let j = hex.index(i, offsetBy: 2)
            let bytes = hex[i..<j]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
            i = j
        }
        self = data
    }
    
    /// AES Decrypt extension (legacy support)
    func aesDecrypt() -> String? {
        // This is a placeholder for legacy support
        // In production, use the proper NFSEncryptionManager
        return String(data: self, encoding: .utf8)
    }
}

// MARK: - String Extensions
public extension String {
    
    /// AES Decrypt extension (legacy support)
    func aesDecrypt() -> String? {
        // This is a placeholder for legacy support
        // In production, use the proper NFSEncryptionManager
        return self
    }
    
    /// Convert string to base64
    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }
    
    /// Convert from base64
    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    /// Generate random string
    static func random(length: Int) -> String {
        let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String((0..<length).map { _ in letters.randomElement()! })
    }
}

// MARK: - Array Extensions
public extension Array where Element == UInt8 {
    
    /// Reveal obfuscated bytes using salt
    func reveal(usingSalt salt: String) -> String {
        let cipher = [UInt8](salt.utf8)
        let length = cipher.count
        var decrypted = [UInt8]()
        
        for (index, element) in self.enumerated() {
            decrypted.append(element ^ cipher[index % length])
        }
        
        guard let decryptUTF = String(bytes: decrypted, encoding: .utf8) else {
            return ""
        }
        
        return decryptUTF.aesDecrypt() ?? decryptUTF
    }
    
    /// Only reveal obfuscated bytes without additional decryption
    func onlyReveal(usingSalt salt: String) -> String {
        let cipher = [UInt8](salt.utf8)
        let length = cipher.count
        var decrypted = [UInt8]()
        
        for (index, element) in self.enumerated() {
            decrypted.append(element ^ cipher[index % length])
        }
        
        return String(bytes: decrypted, encoding: .utf8) ?? ""
    }
}

// MARK: - Bundle Extensions
public extension Bundle {
    
    /// Get app version
    var appVersion: String {
        return infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown"
    }
    
    /// Get build number
    var buildNumber: String {
        return infoDictionary?["CFBundleVersion"] as? String ?? "Unknown"
    }
    
    /// Get bundle identifier
    var bundleIdentifier: String {
        return infoDictionary?["CFBundleIdentifier"] as? String ?? "Unknown"
    }
}

// MARK: - UIDevice Extensions
public extension UIDevice {
    
    /// Check if device is simulator
    var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
    /// Get device model identifier
    var modelIdentifier: String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        return machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
    }
}

// MARK: - FileManager Extensions
public extension FileManager {
    
    /// Check if file exists and is readable
    func isFileReadable(at path: String) -> Bool {
        return fileExists(atPath: path) && isReadableFile(atPath: path)
    }
    
    /// Check if file exists and is writable
    func isFileWritable(at path: String) -> Bool {
        return fileExists(atPath: path) && isWritableFile(atPath: path)
    }
    
    /// Get file size
    func fileSize(at path: String) -> Int64? {
        guard let attributes = try? attributesOfItem(atPath: path) else { return nil }
        return attributes[.size] as? Int64
    }
    
    /// Get file modification date
    func fileModificationDate(at path: String) -> Date? {
        guard let attributes = try? attributesOfItem(atPath: path) else { return nil }
        return attributes[.modificationDate] as? Date
    }
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
