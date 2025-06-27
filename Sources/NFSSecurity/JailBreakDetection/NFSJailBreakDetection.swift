#if canImport(UIKit)
import UIKit
#endif
import MachO

public final class NFSJailbreakController: ObservableObject {
    @Published var isJailbroken: Bool = false
    
    init() {
        self.isJailbroken = NFSJailbreakDetection.isJailbroken()
    }
}

public enum NFSJailbreakDetection {
    
    public static func isJailbroken(config: NFSSecurityConfiguration.JailbreakDetectionConfig? = nil) -> Bool {
        let config = config ?? NFSSecurityConfiguration.JailbreakDetectionConfig()
        
        if config.checkFiles && checkFiles(config: config) {
            return true
        }
        
        if config.checkSystemPaths && checkSystemPaths() {
            return true
        }
        
//        if config.checkSandboxViolations && checkSandboxViolations() {
//            return true
//        }
        
        if config.checkDynamicLibraries && detectDynamicLibraryInjection() {
            return true
        }
        
        if config.checkKernelModifications && hasPatchedKernel() {
            return true
        }
        
        if config.checkCertificateAlterations && hasCertificateAlterations() {
            return true
        }
        
        if config.checkCydiaSources && hasCydiaSources() {
            return true
        }
        
        if config.checkBootSequence && hasModifiedBootSequence() {
            return true
        }
        
        if config.checkPersistentModifications && hasPersistentModifications() {
            return true
        }
        
        if config.checkRuntimeEvasion && hasRuntimeDetectionEvasion() {
            return true
        }
        
        return false
    }

    private static func detectDynamicLibraryInjection() -> Bool {
        let count = _dyld_image_count()
        for i in 0..<count {
            if let name = _dyld_get_image_name(i), String(cString: name).contains("MobileSubstrate") {
                return true
            }
        }
        return false
    }
    
    private static func hasRuntimeDetectionEvasion() -> Bool {
        let filePath = "/tmp/testFile"
        let expectedContent = "test"

        do {
            try expectedContent.write(toFile: filePath, atomically: true, encoding: .utf8)
        } catch {
            return true
        }

        let content = try? String(contentsOfFile: filePath, encoding: .utf8)
        try? FileManager.default.removeItem(atPath: filePath)

        return content != expectedContent
    }
    
    private static func systemForkCall() -> Bool {
        let pid = getpgrp()
        return pid < 0
    }
    
    private static func hasCydiaSources() -> Bool {
        let cydiaSourcesFile = "/etc/apt/sources.list.d/cydia.list"
        return FileManager.default.fileExists(atPath: cydiaSourcesFile)
    }

    private static func hasCertificateAlterations() -> Bool {
        let certificatePath = "/private/var/Keychains/System.keychain"
        return FileManager.default.fileExists(atPath: certificatePath)
    }
    
    private static func hasModifiedSystemConfiguration() -> Bool {
        let configFiles = ["/etc/hosts", "/private/etc/fstab"]
        
        for file in configFiles {
            if FileManager.default.fileExists(atPath: file) {
                return true
            }
        }
        
        return false
    }
    
    private static func hasPersistentModifications() -> Bool {
        let criticalDirectories = ["/Library/MobileSubstrate/DynamicLibraries", "/usr/lib/TweakInject"]
        
        for directory in criticalDirectories {
            if let contents = try? FileManager.default.contentsOfDirectory(atPath: directory), !contents.isEmpty {
                return true
            }
        }
        
        return false
    }
    
    private static func hasModifiedBootSequence() -> Bool {
        let bootSequenceFiles = ["/etc/rc.d"]
        
        for file in bootSequenceFiles {
            if FileManager.default.fileExists(atPath: file) {
                return true
            }
        }
        
        return false
    }
    
    private static func hasPatchedKernel() -> Bool {
        let kernelPath = "/System/Library/Kernels/kernel"
        let originalKernelPath = "/System/Library/Kernels/kernel.orig"
        
        if FileManager.default.fileExists(atPath: originalKernelPath) && FileManager.default.fileExists(atPath: kernelPath) {
            do {
                let kernelData = try Data(contentsOf: URL(fileURLWithPath: kernelPath))
                let originalKernelData = try Data(contentsOf: URL(fileURLWithPath: originalKernelPath))
                
                return kernelData != originalKernelData
            } catch {
                print("❌ Error comparing kernel files: \(error)")
            }
        }
        
        return false
    }
    
    private static func hasSandboxViolations() -> Bool {
        let homeDir = NSHomeDirectory()
        let contents = try? FileManager.default.contentsOfDirectory(atPath: homeDir)
        return contents != nil
    }

    @MainActor private static func openApp(appName: String) -> Bool {
        #if canImport(UIKit)
        let appScheme = "\(appName)://app"
        let appUrl = URL(string: appScheme)

        if let url = appUrl, UIApplication.shared.canOpenURL(url) {
            return true
        } else {
            print("✅ App not installed")
            return false
        }
        #else
        return false
        #endif
    }
    
    private static func checkFiles(config: NFSSecurityConfiguration.JailbreakDetectionConfig) -> Bool {
        let jailbreakFiles = [
            "/Applications/Dopamine.app",
            "/Library/MobileSubstrate/DynamicLibraries/Dopamine.dylib",
            "/Applications/TrollStore.app",
            "/Applications/Sileo.app",
            "/Applications/TrollHelper.app",
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSetttings.app",
            "/Applications/WinterBoard.app",
            "/Applications/blackra1n.app",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/bin/sh",
            "/etc/ssh/sshd_config",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/private/var/lib/apt"
        ] + config.customJailbreakFiles
        
        for file in jailbreakFiles {
            if FileManager.default.fileExists(atPath: file) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkSystemPaths() -> Bool {
        let systemPaths = [
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/Library/MobileSubstrate/CydiaSubstrate.dylib",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/private/var/stash",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/cache/apt/",
            "/private/var/log/syslog",
            "/private/var/tmp/cydia.log",
            "/Applications/WinterBoard.app",
            "/Applications/SBSettings.app",
            "/Applications/MxTube.app",
            "/Applications/IntelliScreen.app",
            "/Applications/Veency.app",
            "/Applications/blackra1n.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/bin/bash",
            "/bin/sh",
            "/etc/apt",
            "/etc/ssh/sshd_config",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/private/var/lib/apt"
        ]
        
        for path in systemPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    private static func canWriteToSystem() -> Bool {
        let systemPaths = ["/Applications", "/Library", "/System"]
        
        for path in systemPaths {
            if FileManager.default.isWritableFile(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    private static func canAccessRestrictedAreas() -> Bool {
        let restrictedPaths = ["/private/var/mobile/Library/Preferences/", "/private/var/mobile/Library/"]
        
        for path in restrictedPaths {
            if FileManager.default.isWritableFile(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    private static func hasSuspiciousSymlinks() -> Bool {
        let suspiciousSymlinks = ["/Applications", "/Library/Ringtones", "/Library/Wallpaper", "/usr/arm-apple-darwin9", "/usr/include", "/usr/libexec", "/usr/share"]
        
        for symlink in suspiciousSymlinks {
            if let attributes = try? FileManager.default.attributesOfItem(atPath: symlink),
               let fileType = attributes[.type] as? FileAttributeType,
               fileType == .typeSymbolicLink {
                return true
            }
        }
        
        return false
    }
    
    private static func isSuspiciousSystemPathsExists() -> Bool {
        let suspiciousPaths = ["/private/var/lib/apt/", "/private/var/lib/cydia", "/private/var/mobile/Library/SBSettings/Themes"]
        
        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    @MainActor private static func isZebraInstalled() -> Bool {
        return openApp(appName: "Zebra")
    }
    
    @MainActor private static func isSileoInstalled() -> Bool {
        return openApp(appName: "Sileo")
    }
    
    @MainActor private static func isInstaller5Installed() -> Bool {
        return openApp(appName: "Installer")
    }
    
    @MainActor private static func isCydiaInstalled() -> Bool {
        return openApp(appName: "Cydia")
    }
}
