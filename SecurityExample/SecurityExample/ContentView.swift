//
//  ContentView.swift
//  SecurityExample
//
//  Created by Muhammad Ahmad Munir on 27/06/2025.
//

import SwiftUI
import NFSSecurity

struct ContentView: View {
    @StateObject private var viewModel = ContentViewModel()
    
    var body: some View {
        NavigationView {
            ScrollView {
                LazyVStack(spacing: 24) {
                    // Header
                    headerSection
                    
                    // Security Operations
                    securityOperationsSection
                    
                    // Security Checks
                    securityChecksSection
                    
                    // Biometric Authentication
                    biometricSection
                    
                    // Advanced Features
                    advancedFeaturesSection
                }
                .padding()
            }
            .navigationTitle("NFSSecurity")
            .navigationBarTitleDisplayMode(.large)
            .background(Color(.systemGroupedBackground))
        }
    }
    
    // MARK: - Header Section
    private var headerSection: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.checkered.fill")
                .font(.system(size: 60))
                .foregroundColor(.blue)
                .symbolEffect(.bounce, options: .repeating)
            
            VStack(spacing: 8) {
                Text("NFSSecurity Framework")
                    .font(.title2)
                    .fontWeight(.bold)
                
                Text("Comprehensive iOS Security Toolkit")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(24)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: .black.opacity(0.1), radius: 8, x: 0, y: 2)
        )
    }
    
    // MARK: - Security Operations Section
    private var securityOperationsSection: some View {
        VStack(alignment: .leading, spacing: 20) {
            SectionHeader(title: "Security Operations", icon: "lock.shield.fill")
            
            // Input Section
            VStack(alignment: .leading, spacing: 12) {
                Text("Input Text")
                    .font(.headline)
                    .foregroundColor(.primary)
                
                TextField("Enter text to process...", text: $viewModel.inputText, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(3...6)
            }
            
            // Algorithm Selection
            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Hashing")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    
                    Picker("Hashing Algorithm", selection: $viewModel.selectedHashingAlgorithm) {
                        ForEach(HashingAlgorithm.allCases, id: \.self) { algorithm in
                            Text(algorithm.rawValue).tag(algorithm)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                }
                
                Spacer()
                
                VStack(alignment: .leading, spacing: 8) {
                    Text("Encryption")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    
                    Picker("Encryption Algorithm", selection: $viewModel.selectedEncryptionAlgorithm) {
                        ForEach(EncryptionAlgorithm.allCases, id: \.self) { algorithm in
                            Text(algorithm.rawValue).tag(algorithm)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                }
            }
            
            // Encryption Key (only show for encryption/decryption)
            if viewModel.selectedEncryptionAlgorithm != .sha256 && viewModel.selectedEncryptionAlgorithm != .sha512 {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Encryption Key")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    
                    SecureField("Enter encryption key", text: $viewModel.encryptionKey)
                        .textFieldStyle(.roundedBorder)
                }
            }
            
            // Action Buttons
            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
                GridItem(.flexible())
            ], spacing: 12) {
                ActionButton(
                    title: "Hash",
                    icon: "function",
                    color: .blue,
                    isLoading: viewModel.isProcessing
                ) {
                    viewModel.performHashing()
                }
                
                ActionButton(
                    title: "Encrypt",
                    icon: "lock.fill",
                    color: .green,
                    isLoading: viewModel.isProcessing
                ) {
                    viewModel.performEncryption()
                }
                
                ActionButton(
                    title: "Decrypt",
                    icon: "lock.open.fill",
                    color: .orange,
                    isLoading: viewModel.isProcessing
                ) {
                    viewModel.performDecryption()
                }
            }
            
            // Hash Verification
            VStack(alignment: .leading, spacing: 12) {
                Text("Hash Verification")
                    .font(.headline)
                    .foregroundColor(.primary)
                
                TextField("Enter hash to verify against", text: $viewModel.hashToVerify)
                    .textFieldStyle(.roundedBorder)
                
                ActionButton(
                    title: "Verify Hash",
                    icon: "checkmark.shield.fill",
                    color: .purple,
                    isLoading: viewModel.isProcessing
                ) {
                    viewModel.verifyHash()
                }
                
                if !viewModel.hashVerificationResult.isEmpty {
                    HStack {
                        HStack {
                            Image(systemName: viewModel.isHashValid ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundColor(viewModel.isHashValid ? .green : .red)
                            Text(viewModel.hashVerificationResult)
                                .font(.subheadline)
                                .foregroundColor(viewModel.isHashValid ? .green : .red)
                        }
                        
                        Spacer()
                        
                        Button(action: {
                            UIPasteboard.general.string = viewModel.outputText
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "doc.on.doc")
                                Text("Copy Hash")
                            }
                            .font(.caption)
                            .foregroundColor(.blue)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(viewModel.isHashValid ? Color.green.opacity(0.1) : Color.red.opacity(0.1))
                    )
                }
            }
            
            // Output Section
            if !viewModel.outputText.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Result")
                            .font(.headline)
                            .foregroundColor(.primary)
                        
                        Spacer()
                        
                        Button(action: {
                            UIPasteboard.general.string = viewModel.outputText
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "doc.on.doc")
                                Text("Copy")
                            }
                            .font(.caption)
                            .foregroundColor(.blue)
                        }
                        .buttonStyle(.plain)
                    }
                    
                    ScrollView {
                        Text(viewModel.outputText)
                            .font(.system(.body, design: .monospaced))
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color(.systemGray6))
                            )
                    }
                    .frame(maxHeight: 120)
                }
            }
            
            // Status Messages
            if !viewModel.errorMessage.isEmpty {
                StatusMessage(message: viewModel.errorMessage, type: .error)
            }
            
            if !viewModel.successMessage.isEmpty {
                StatusMessage(message: viewModel.successMessage, type: .success)
            }
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: .black.opacity(0.1), radius: 8, x: 0, y: 2)
        )
    }
    
    // MARK: - Security Checks Section
    private var securityChecksSection: some View {
        VStack(alignment: .leading, spacing: 20) {
            SectionHeader(title: "Security Checks", icon: "magnifyingglass.circle.fill")
            
            ActionButton(
                title: "Run Security Checks",
                icon: "shield.checkered",
                color: .blue,
                isLoading: false
            ) {
                viewModel.performSecurityChecks()
            }
            
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                SecurityCheckCard(title: "Debugger", result: viewModel.debuggerResult, icon: "ladybug")
                SecurityCheckCard(title: "Jailbreak", result: viewModel.jailbreakResult, icon: "exclamationmark.triangle")
                SecurityCheckCard(title: "Simulator", result: viewModel.simulatorResult, icon: "iphone")
                SecurityCheckCard(title: "Reverse Engineering", result: viewModel.reverseEngineeringResult, icon: "wrench.and.screwdriver")
                SecurityCheckCard(title: "Proxy", result: viewModel.proxyResult, icon: "network")
                SecurityCheckCard(title: "Integrity", result: viewModel.integrityResult, icon: "checkmark.shield")
            }
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: .black.opacity(0.1), radius: 8, x: 0, y: 2)
        )
    }
    
    // MARK: - Biometric Section
    private var biometricSection: some View {
        VStack(alignment: .leading, spacing: 20) {
            SectionHeader(title: "Biometric Authentication", icon: "faceid")
            
            if !viewModel.availableBiometricTypes.isEmpty {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Available Biometric Types")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    
                    HStack(spacing: 16) {
                        ForEach(viewModel.availableBiometricTypes, id: \.self) { type in
                            HStack(spacing: 8) {
                                Image(systemName: type.icon)
                                    .foregroundColor(.blue)
                                Text(type.rawValue)
                                    .font(.caption)
                                    .fontWeight(.medium)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color.blue.opacity(0.1))
                            )
                        }
                    }
                }
            }
            
            ActionButton(
                title: "Test Biometric Auth",
                icon: "faceid",
                color: .blue,
                isLoading: false
            ) {
                viewModel.testBiometricAuthentication()
            }
            
            if !viewModel.biometricResult.isEmpty {
                StatusMessage(
                    message: viewModel.biometricResult,
                    type: viewModel.biometricResult.contains("✅") ? .success : .error
                )
            }
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: .black.opacity(0.1), radius: 8, x: 0, y: 2)
        )
    }
    
    // MARK: - Advanced Features Section
    private var advancedFeaturesSection: some View {
        VStack(alignment: .leading, spacing: 20) {
            SectionHeader(title: "Advanced Features", icon: "star.fill")
            
            // Keychain Operations
            VStack(alignment: .leading, spacing: 12) {
                Text("Keychain Operations")
                    .font(.headline)
                    .foregroundColor(.primary)
                
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Key")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextField("Key", text: $viewModel.keychainKey)
                            .textFieldStyle(.roundedBorder)
                    }
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Value")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextField("Value", text: $viewModel.keychainValue)
                            .textFieldStyle(.roundedBorder)
                    }
                }
                
                ActionButton(
                    title: "Test Keychain",
                    icon: "key.fill",
                    color: .green,
                    isLoading: false
                ) {
                    viewModel.testKeychainOperations()
                }
                
                if !viewModel.keychainRetrievedValue.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("Retrieved Value")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            
                            Spacer()
                            
                            Button(action: {
                                UIPasteboard.general.string = viewModel.keychainRetrievedValue
                            }) {
                                HStack(spacing: 2) {
                                    Image(systemName: "doc.on.doc")
                                    Text("Copy")
                                }
                                .font(.caption2)
                                .foregroundColor(.blue)
                            }
                            .buttonStyle(.plain)
                        }
                        
                        Text(viewModel.keychainRetrievedValue)
                            .font(.system(.caption, design: .monospaced))
                            .padding(8)
                            .background(
                                RoundedRectangle(cornerRadius: 6)
                                    .fill(Color(.systemGray6))
                            )
                    }
                }
                
                if !viewModel.keychainResult.isEmpty {
                    StatusMessage(
                        message: viewModel.keychainResult,
                        type: viewModel.keychainResult.contains("✅") ? .success : .error
                    )
                }
            }
            
            Divider()
            
            // Random Generation
            VStack(alignment: .leading, spacing: 12) {
                Text("Random Generation")
                    .font(.headline)
                    .foregroundColor(.primary)
                
                HStack {
                    Text("Length: \(viewModel.randomLength)")
                        .font(.subheadline)
                    
                    Spacer()
                    
                    Slider(value: Binding(
                        get: { Double(viewModel.randomLength) },
                        set: { viewModel.randomLength = Int($0) }
                    ), in: 8...64, step: 1)
                    .frame(width: 120)
                }
                
                Picker("Character Set", selection: $viewModel.selectedRandomCharacterSet) {
                    ForEach(RandomCharacterSet.allCases, id: \.self) { set in
                        Text(set.rawValue).tag(set)
                    }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                
                ActionButton(
                    title: "Generate Random",
                    icon: "dice.fill",
                    color: .purple,
                    isLoading: false
                ) {
                    viewModel.generateRandomData()
                }
                
                if !viewModel.generatedRandomString.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        ResultCard(title: "Random String", value: viewModel.generatedRandomString)
                        ResultCard(title: "Secure Password", value: viewModel.generatedPassword)
                        ResultCard(title: "UUID", value: viewModel.generatedUUID)
                    }
                }
                
                if !viewModel.randomGenerationResult.isEmpty {
                    StatusMessage(
                        message: viewModel.randomGenerationResult,
                        type: viewModel.randomGenerationResult.contains("✅") ? .success : .error
                    )
                }
            }
            
            Divider()
            
            // Integrity & Network Security
            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Integrity Check")
                        .font(.headline)
                        .foregroundColor(.primary)
                    
                    ActionButton(
                        title: "Check Integrity",
                        icon: "checkmark.shield.fill",
                        color: .blue,
                        isLoading: false
                    ) {
                        viewModel.performIntegrityCheck()
                    }
                    
                    if !viewModel.integrityCheckResult.isEmpty {
                        StatusMessage(
                            message: viewModel.integrityCheckResult,
                            type: viewModel.isIntegrityValid ? .success : .error
                        )
                    }
                }
                
                Spacer()
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("Network Security")
                        .font(.headline)
                        .foregroundColor(.primary)
                    
                    ActionButton(
                        title: "Check Network",
                        icon: "network",
                        color: .green,
                        isLoading: false
                    ) {
                        viewModel.performNetworkSecurityCheck()
                    }
                    
                    if !viewModel.networkSecurityCheckResult.isEmpty {
                        StatusMessage(
                            message: viewModel.networkSecurityCheckResult,
                            type: viewModel.isNetworkSecure ? .success : .error
                        )
                    }
                }
            }
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: .black.opacity(0.1), radius: 8, x: 0, y: 2)
        )
    }
}

// MARK: - Supporting Views
struct SectionHeader: View {
    let title: String
    let icon: String
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(.blue)
            
            Text(title)
                .font(.title2)
                .fontWeight(.bold)
        }
    }
}

struct ActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let isLoading: Bool
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.8)
                        .tint(.white)
                } else {
                    Image(systemName: icon)
                }
                Text(title)
                    .fontWeight(.medium)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(color)
            )
            .foregroundColor(.white)
        }
        .disabled(isLoading)
    }
}

struct SecurityCheckCard: View {
    let title: String
    let result: String
    let icon: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(.blue)
                Text(title)
                    .font(.caption)
                    .fontWeight(.medium)
                Spacer()
            }
            
            if !result.isEmpty {
                HStack {
                    Image(systemName: result.contains("✅") ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(result.contains("✅") ? .green : .red)
                    Text(result)
                        .font(.caption2)
                        .foregroundColor(result.contains("✅") ? .green : .red)
                    Spacer()
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(.systemGray6))
        )
    }
}

struct StatusMessage: View {
    let message: String
    let type: MessageType
    
    enum MessageType {
        case success, error
        
        var color: Color {
            switch self {
            case .success: return .green
            case .error: return .red
            }
        }
        
        var icon: String {
            switch self {
            case .success: return "checkmark.circle.fill"
            case .error: return "xmark.circle.fill"
            }
        }
    }
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: type.icon)
                .foregroundColor(type.color)
            Text(message)
                .font(.subheadline)
                .foregroundColor(type.color)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(type.color.opacity(0.1))
        )
    }
}

struct ResultCard: View {
    let title: String
    let value: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                Spacer()
                
                Button(action: {
                    UIPasteboard.general.string = value
                }) {
                    HStack(spacing: 2) {
                        Image(systemName: "doc.on.doc")
                        Text("Copy")
                    }
                    .font(.caption2)
                    .foregroundColor(.blue)
                }
                .buttonStyle(.plain)
            }
            
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .padding(6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(Color(.systemGray6))
                )
        }
    }
}

#Preview {
    ContentView()
}
