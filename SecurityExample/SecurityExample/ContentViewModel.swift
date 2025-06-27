//
//  ContentViewModel.swift
//  SecurityExample
//
//  Created by Muhammad Ahmad Munir on 27/06/2025.
//

import Foundation
import NFSSecurity
import SwiftUI

@MainActor
class ContentViewModel: ObservableObject {
    
    // MARK: - Published Properties
    @Published var inputText = ""
    @Published var outputText = ""
    @Published var hashToVerify = ""
    @Published var selectedHashingAlgorithm: HashingAlgorithm = .sha256
    @Published var selectedEncryptionAlgorithm: EncryptionAlgorithm = .aes256
    @Published var encryptionKey = ""
    @Published var isProcessing = false
    @Published var errorMessage = ""
    @Published var successMessage = ""
    
    // MARK: - Security Check Results
    @Published var debuggerResult = ""
    @Published var jailbreakResult = ""
    @Published var simulatorResult = ""
    @Published var reverseEngineeringResult = ""
    @Published var proxyResult = ""
    @Published var integrityResult = ""
    @Published var networkSecurityResult = ""
    
    // MARK: - Advanced Security Results
    @Published var biometricResult = ""
    @Published var keychainResult = ""
    @Published var randomGenerationResult = ""
    @Published var integrityCheckResult = ""
    @Published var networkSecurityCheckResult = ""
    
    // MARK: - Biometric Properties
    @Published var availableBiometricTypes: [BiometricType] = []
    @Published var selectedBiometricType: BiometricType = .none
    
    // MARK: - Keychain Properties
    @Published var keychainKey = "test_key"
    @Published var keychainValue = "test_value"
    @Published var keychainRetrievedValue = ""
    
    // MARK: - Random Generation Properties
    @Published var randomLength = 32
    @Published var selectedRandomCharacterSet: RandomCharacterSet = .numeric
    @Published var generatedRandomString = ""
    @Published var generatedPassword = ""
    @Published var generatedUUID = ""
    
    // MARK: - Integrity Properties
    @Published var integrityIssues: [String] = []
    @Published var isIntegrityValid = false
    
    // MARK: - Network Security Properties
    @Published var networkSecurityIssues: [String] = []
    @Published var isNetworkSecure = false
    
    // MARK: - Hash Verification Properties
    @Published var hashVerificationResult = ""
    @Published var isHashValid = false
    
    // MARK: - Initialization
    init() {
        loadAvailableBiometricTypes()
    }
    
    // MARK: - Public Methods
    
    func performHashing() {
        guard !inputText.isEmpty else {
            showError("Please enter text to hash")
            return
        }
        
        isProcessing = true
        clearMessages()
        
        Task {
            do {
                let hashedData = try NFSSecurity.shared.hash(inputText, using: selectedHashingAlgorithm)
                let hashedString = hashedData.map { String(format: "%02x", $0) }.joined()
                
                await MainActor.run {
                    outputText = hashedString
                    showSuccess("Hashing completed successfully")
                    isProcessing = false
                }
            } catch {
                await MainActor.run {
                    showError("Hashing failed: \(error.localizedDescription)")
                    isProcessing = false
                }
            }
        }
    }
    
    func verifyHash() {
        guard !inputText.isEmpty else {
            showError("Please enter text to verify")
            return
        }
        
        guard !hashToVerify.isEmpty else {
            showError("Please enter hash to verify against")
            return
        }
        
        isProcessing = true
        clearMessages()
        
        Task {
            do {
                let hashedData = try NFSSecurity.shared.hash(inputText, using: selectedHashingAlgorithm)
                let hashedString = hashedData.map { String(format: "%02x", $0) }.joined()
                
                let isValid = hashedString.lowercased() == hashToVerify.lowercased()
                
                await MainActor.run {
                    isHashValid = isValid
                    hashVerificationResult = isValid ? "✅ Hash verification successful" : "❌ Hash verification failed"
                    showSuccess(isValid ? "Hash verification successful" : "Hash verification failed")
                    isProcessing = false
                }
            } catch {
                await MainActor.run {
                    showError("Hash verification failed: \(error.localizedDescription)")
                    isProcessing = false
                }
            }
        }
    }
    
    func performEncryption() {
        guard !inputText.isEmpty else {
            showError("Please enter text to encrypt")
            return
        }
        
        guard !encryptionKey.isEmpty else {
            showError("Please enter an encryption key")
            return
        }
        
        isProcessing = true
        clearMessages()
        
        Task {
            do {
                guard let inputData = inputText.data(using: .utf8) else {
                    throw NFSSecurityError.invalidData
                }
                
                let encryptedData = try NFSSecurity.shared.encrypt(inputData, using: selectedEncryptionAlgorithm, withKey: encryptionKey)
                let encryptedString = encryptedData.base64EncodedString()
                
                await MainActor.run {
                    outputText = encryptedString
                    showSuccess("Encryption completed successfully")
                    isProcessing = false
                }
            } catch {
                await MainActor.run {
                    showError("Encryption failed: \(error.localizedDescription)")
                    isProcessing = false
                }
            }
        }
    }
    
    func performDecryption() {
        guard !inputText.isEmpty else {
            showError("Please enter encrypted data to decrypt")
            return
        }
        
        guard !encryptionKey.isEmpty else {
            showError("Please enter the decryption key")
            return
        }
        
        isProcessing = true
        clearMessages()
        
        Task {
            do {
                guard let encryptedData = Data(base64Encoded: inputText) else {
                    throw NFSSecurityError.invalidData
                }
                
                let decryptedData = try NFSSecurity.shared.decrypt(encryptedData, using: selectedEncryptionAlgorithm, withKey: encryptionKey)
                
                guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                    throw NFSSecurityError.invalidData
                }
                
                await MainActor.run {
                    outputText = decryptedString
                    showSuccess("Decryption completed successfully")
                    isProcessing = false
                }
            } catch {
                await MainActor.run {
                    showError("Decryption failed: \(error.localizedDescription)")
                    isProcessing = false
                }
            }
        }
    }
    
    func performSecurityChecks() {
        Task {
            await performSecurityDetection()
        }
    }
    
    // MARK: - Advanced Security Methods
    
    func testBiometricAuthentication() {
        Task {
            do {
                let isAvailable = NFSSecurity.shared.isBiometricAvailable()
                if isAvailable {
                    let authenticated = try await NFSSecurity.shared.authenticateWithBiometrics(reason: "Test biometric authentication")
                    await MainActor.run {
                        biometricResult = authenticated ? "✅ Biometric authentication successful" : "❌ Biometric authentication failed"
                    }
                } else {
                    await MainActor.run {
                        biometricResult = "❌ Biometric authentication not available"
                    }
                }
            } catch {
                await MainActor.run {
                    biometricResult = "❌ Biometric authentication error: \(error.localizedDescription)"
                }
            }
        }
    }
    
    func testKeychainOperations() {
        Task {
            do {
                // Store value
                try NFSSecurity.shared.storeStringInKeychain(keychainValue, forKey: keychainKey)
                
                // Retrieve value
                let retrievedValue = try NFSSecurity.shared.retrieveStringFromKeychain(forKey: keychainKey)
                
                await MainActor.run {
                    keychainRetrievedValue = retrievedValue
                    keychainResult = "✅ Keychain operations successful"
                }
            } catch {
                await MainActor.run {
                    keychainResult = "❌ Keychain operations failed: \(error.localizedDescription)"
                }
            }
        }
    }
    
    func generateRandomData() {
        Task {
            do {
                let randomString = try NFSSecurity.shared.generateRandomString(length: randomLength, characterSet: selectedRandomCharacterSet)
                let password = try NFSSecurity.shared.generateSecurePassword(length: randomLength)
                let uuid = NFSSecurity.shared.generateUUID()
                
                await MainActor.run {
                    generatedRandomString = randomString
                    generatedPassword = password
                    generatedUUID = uuid.uuidString
                    randomGenerationResult = "✅ Random data generated successfully"
                }
            } catch {
                await MainActor.run {
                    randomGenerationResult = "❌ Random generation failed: \(error.localizedDescription)"
                }
            }
        }
    }
    
    func performIntegrityCheck() {
        Task {
            do {
                let result = NFSSecurity.shared.performIntegrityCheck()
                
                await MainActor.run {
                    isIntegrityValid = result.isIntegrityValid
                    integrityIssues = result.issues
                    integrityCheckResult = result.isIntegrityValid ? "✅ Integrity check passed" : "❌ Integrity check failed"
                }
            } catch {
                await MainActor.run {
                    integrityCheckResult = "❌ Integrity check error: \(error.localizedDescription)"
                }
            }
        }
    }
    
    func performNetworkSecurityCheck() {
        Task {
            do {
                let result = NFSSecurity.shared.checkNetworkSecurity()
                
                await MainActor.run {
                    isNetworkSecure = result.isSecure
                    networkSecurityIssues = result.issues
                    networkSecurityCheckResult = result.isSecure ? "✅ Network security check passed" : "❌ Network security check failed"
                }
            } catch {
                await MainActor.run {
                    networkSecurityCheckResult = "❌ Network security check error: \(error.localizedDescription)"
                }
            }
        }
    }
    
    // MARK: - Private Methods
    
    private func performSecurityDetection() async {
        // Debugger detection
        let isDebuggerAttached = NFSSecurity.shared.isDebuggerAttached()
        debuggerResult = isDebuggerAttached ? "❌ Debugger detected" : "✅ No debugger detected"
        
        // Jailbreak detection
        let isJailbroken = NFSSecurity.shared.isJailbroken()
        jailbreakResult = isJailbroken ? "❌ Jailbreak detected" : "✅ No jailbreak detected"
        
        // Simulator detection
        let isSimulator = NFSSecurity.shared.isRunningInSimulator()
        simulatorResult = isSimulator ? "❌ Simulator detected" : "✅ Real device detected"
        
        // Reverse engineering detection
        let isReverseEngineered = NFSSecurity.shared.isReverseEngineeringToolsDetected()
        reverseEngineeringResult = isReverseEngineered ? "❌ Reverse engineering detected" : "✅ No reverse engineering detected"
        
        // Proxy detection
        let isProxyEnabled = NFSSecurity.shared.detectProxy()
        proxyResult = isProxyEnabled ? "❌ Proxy detected" : "✅ No proxy detected"
        
        // Integrity check
        do {
            let result = NFSSecurity.shared.performIntegrityCheck()
            integrityResult = result.isIntegrityValid ? "✅ Integrity check passed" : "❌ Integrity check failed"
        } catch {
            integrityResult = "❌ Integrity check error"
        }
        
        // Network security check
        do {
            let result = NFSSecurity.shared.checkNetworkSecurity()
            networkSecurityResult = result.isSecure ? "✅ Network security passed" : "❌ Network security failed"
        } catch {
            networkSecurityResult = "❌ Network security error"
        }
    }
    
    private func loadAvailableBiometricTypes() {
        availableBiometricTypes = NFSSecurity.shared.getAvailableBiometricTypes()
        if let firstType = availableBiometricTypes.first {
            selectedBiometricType = firstType
        }
    }
    
    private func showError(_ message: String) {
        errorMessage = message
        successMessage = ""
    }
    
    private func showSuccess(_ message: String) {
        successMessage = message
        errorMessage = ""
    }
    
    private func clearMessages() {
        errorMessage = ""
        successMessage = ""
    }
}
