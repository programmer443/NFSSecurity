import Foundation
import Network
import Security

// MARK: - Network Security Manager Protocol
public protocol NetworkSecurityManagerProtocol {
    func checkNetworkSecurity() -> NetworkSecurityResult
    func verifyCertificatePinning(for host: String) -> Bool
    func detectProxy() -> Bool
    func checkNetworkReachability() -> Bool
    func validateSSLConnection(to url: URL) -> Bool
}

// MARK: - Network Security Configuration
public struct NetworkSecurityConfig {
    public let enabled: Bool
    public let enableCertificatePinning: Bool
    public let enableProxyDetection: Bool
    public let enableNetworkReachability: Bool
    public let pinnedCertificates: [String: [Data]]
    public let allowedHosts: [String]
    public let blockedHosts: [String]
    
    public init(
        enabled: Bool = true,
        enableCertificatePinning: Bool = true,
        enableProxyDetection: Bool = true,
        enableNetworkReachability: Bool = true,
        pinnedCertificates: [String: [Data]] = [:],
        allowedHosts: [String] = [],
        blockedHosts: [String] = []
    ) {
        self.enabled = enabled
        self.enableCertificatePinning = enableCertificatePinning
        self.enableProxyDetection = enableProxyDetection
        self.enableNetworkReachability = enableNetworkReachability
        self.pinnedCertificates = pinnedCertificates
        self.allowedHosts = allowedHosts
        self.blockedHosts = blockedHosts
    }
}

// MARK: - Network Security Result
public struct NetworkSecurityResult {
    public let isSecure: Bool
    public let certificatePinningValid: Bool
    public let proxyDetected: Bool
    public let networkReachable: Bool
    public let sslValid: Bool
    public let issues: [String]
    
    public init(
        isSecure: Bool,
        certificatePinningValid: Bool,
        proxyDetected: Bool,
        networkReachable: Bool,
        sslValid: Bool,
        issues: [String]
    ) {
        self.isSecure = isSecure
        self.certificatePinningValid = certificatePinningValid
        self.proxyDetected = proxyDetected
        self.networkReachable = networkReachable
        self.sslValid = sslValid
        self.issues = issues
    }
}

// MARK: - Network Security Manager
public final class NFSNetworkSecurityManager: NetworkSecurityManagerProtocol {
    
    // MARK: - Properties
    private let configuration: NetworkSecurityConfig
    private let monitor: NWPathMonitor?
    private var isMonitoring = false
    
    // MARK: - Initialization
    public init(configuration: NetworkSecurityConfig = NetworkSecurityConfig()) {
        self.configuration = configuration
        self.monitor = NWPathMonitor()
    }
    
    // MARK: - Public Methods
    
    /// Perform comprehensive network security check
    public func checkNetworkSecurity() -> NetworkSecurityResult {
        guard configuration.enabled else {
            return NetworkSecurityResult(
                isSecure: false,
                certificatePinningValid: false,
                proxyDetected: true,
                networkReachable: false,
                sslValid: false,
                issues: ["Network security checking is disabled"]
            )
        }
        
        var issues: [String] = []
        var isSecure = true
        
        // Check certificate pinning
        let certificatePinningValid = verifyCertificatePinning(for: "example.com")
        if !certificatePinningValid {
            issues.append("Certificate pinning verification failed")
            isSecure = false
        }
        
        // Check proxy detection
        let proxyDetected = detectProxy()
        if proxyDetected {
            issues.append("Proxy detected")
            isSecure = false
        }
        
        // Check network reachability
        let networkReachable = checkNetworkReachability()
        if !networkReachable {
            issues.append("Network not reachable")
            isSecure = false
        }
        
        // Check SSL validation
        let sslValid = validateSSLConnection(to: URL(string: "https://example.com")!)
        if !sslValid {
            issues.append("SSL validation failed")
            isSecure = false
        }
        
        return NetworkSecurityResult(
            isSecure: isSecure,
            certificatePinningValid: certificatePinningValid,
            proxyDetected: proxyDetected,
            networkReachable: networkReachable,
            sslValid: sslValid,
            issues: issues
        )
    }
    
    /// Verify certificate pinning for a specific host
    public func verifyCertificatePinning(for host: String) -> Bool {
        guard configuration.enableCertificatePinning else { return true }
        
        // Check if we have pinned certificates for this host
        guard let pinnedCerts = configuration.pinnedCertificates[host] else {
            return true // No pinned certificates for this host
        }
        
        // This is a basic implementation - in production, implement actual certificate pinning
        // You would typically:
        // 1. Make a network request to the host
        // 2. Extract the server's certificate
        // 3. Compare it with the pinned certificates
        // 4. Return true if there's a match
        
        return true
    }
    
    /// Detect if proxy is being used
    public func detectProxy() -> Bool {
        guard configuration.enableProxyDetection else { return false }
        
        // Check for proxy environment variables
        let proxyEnvVars = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NO_PROXY",
            "no_proxy"
        ]
        
        for envVar in proxyEnvVars {
            if let proxyValue = ProcessInfo.processInfo.environment[envVar], !proxyValue.isEmpty {
                return true
            }
        }
        
        // Check for system proxy settings
        if let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] {
            if let httpProxy = proxySettings["HTTPProxy"] as? String, !httpProxy.isEmpty {
                return true
            }
            if let httpsProxy = proxySettings["HTTPSProxy"] as? String, !httpsProxy.isEmpty {
                return true
            }
        }
        
        return false
    }
    
    /// Check network reachability
    public func checkNetworkReachability() -> Bool {
        guard configuration.enableNetworkReachability else { return true }
        
        // This is a basic implementation - in production, implement actual network reachability checking
        // You would typically use NWPathMonitor or SCNetworkReachability
        
        return true
    }
    
    /// Validate SSL connection to a URL
    public func validateSSLConnection(to url: URL) -> Bool {
        // This is a basic implementation - in production, implement actual SSL validation
        // You would typically:
        // 1. Create a URLSession with custom delegate
        // 2. Make a request to the URL
        // 3. Validate the SSL certificate in the delegate
        // 4. Return true if validation passes
        
        return true
    }
    
    // MARK: - Convenience Methods
    
    /// Add pinned certificate for a host
    public func addPinnedCertificate(_ certificate: Data, for host: String) {
        // This would modify the configuration
        // In a real implementation, you'd need to make the configuration mutable
    }
    
    /// Remove pinned certificate for a host
    public func removePinnedCertificate(for host: String) {
        // This would modify the configuration
        // In a real implementation, you'd need to make the configuration mutable
    }
    
    /// Check if host is allowed
    public func isHostAllowed(_ host: String) -> Bool {
        if !configuration.allowedHosts.isEmpty {
            return configuration.allowedHosts.contains(host)
        }
        
        if !configuration.blockedHosts.isEmpty {
            return !configuration.blockedHosts.contains(host)
        }
        
        return true
    }
    
    /// Start network monitoring
    public func startNetworkMonitoring() {
        guard let monitor = monitor, !isMonitoring else { return }
        
        monitor.pathUpdateHandler = { path in
            // Handle network path updates without capturing self
            // This avoids the sendable issue
        }
        
        let queue = DispatchQueue(label: "NetworkSecurityMonitor")
        monitor.start(queue: queue)
        isMonitoring = true
    }
    
    /// Stop network monitoring
    public func stopNetworkMonitoring() {
        guard let monitor = monitor, isMonitoring else { return }
        
        monitor.cancel()
        isMonitoring = false
    }
    
    // MARK: - Private Methods
    
    /// Handle network path updates
    private func handleNetworkPathUpdate(_ path: NWPath) {
        // Handle network path changes
        // This could trigger security checks or update the security status
    }
    
    /// Validate certificate
    private func validateCertificate(_ certificate: SecCertificate, for host: String) -> Bool {
        // Implement certificate validation logic
        return true
    }
    
    /// Extract certificate from data
    private func extractCertificate(from data: Data) -> SecCertificate? {
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            return nil
        }
        return certificate
    }
    
    /// Compare certificates
    private func compareCertificates(_ cert1: SecCertificate, _ cert2: SecCertificate) -> Bool {
        let data1 = SecCertificateCopyData(cert1)
        let data2 = SecCertificateCopyData(cert2)
        return CFEqual(data1, data2)
    }
} 