import Foundation
#if canImport(UIKit)
import UIKit
#endif
import Darwin // fork
import MachO // dyld
import ObjectiveC // NSObject and Selector

internal class JailbreakChecker {
  typealias CheckResult = (passed: Bool, failMessage: String)
  
  struct JailbreakStatus {
    let passed: Bool
    let failMessage: String // Added for backwards compatibility
    let failedChecks: [FailedCheckType]
  }
  
    @MainActor static func amIJailbroken() -> Bool {
    return !performChecks().passed
  }
  
    @MainActor static func amIJailbrokenWithFailMessage() -> (jailbroken: Bool, failMessage: String) {
    let status = performChecks()
    return (!status.passed, status.failMessage)
  }
  
    @MainActor static func amIJailbrokenWithFailedChecks() -> (jailbroken: Bool,
                                                  failedChecks: [FailedCheckType]) {
    let status = performChecks()
    return (!status.passed, status.failedChecks)
  }
  
    @MainActor private static func performChecks() -> JailbreakStatus {
    var passed = true
    var failMessage = ""
    var failedChecks: [FailedCheckType] = []
    
    for check in FailedCheck.allCases {
      let result = getResult(from: check)
      
      passed = passed && result.passed
      
      if !result.passed {
        failedChecks.append((check: check, failMessage: result.failMessage))
        
        if !failMessage.isEmpty {
          failMessage += ", "
        }
      }
      
      failMessage += result.failMessage
    }
    
    return JailbreakStatus(passed: passed, failMessage: failMessage, failedChecks: failedChecks)
  }
  
    @MainActor private static func getResult(from check: FailedCheck) -> CheckResult {
    switch check {
    case .urlSchemes:
      return checkURLSchemes()
    case .existenceOfSuspiciousFiles:
      return checkExistenceOfSuspiciousFiles()
    case .suspiciousFilesCanBeOpened:
      return checkSuspiciousFilesCanBeOpened()
    case .restrictedDirectoriesWriteable:
      return checkRestrictedDirectoriesWriteable()
    case .fork:
      if !NFSEmulatorChecker.amIRunInEmulator() {
        return checkFork()
      } else {
        print("App run in the emulator, skipping the fork check.")
        return (true, "")
      }
    case .symbolicLinks:
      return checkSymbolicLinks()
    case .dyld:
      return checkDYLD()
    case .suspiciousObjCClasses:
      return checkSuspiciousObjCClasses()
    default:
      return (true, "")
    }
  }
  
    @MainActor private static func canOpenUrlFromList(urlSchemes: [String]) -> CheckResult {
    #if canImport(UIKit)
    for urlScheme in urlSchemes {
      if let url = URL(string: urlScheme) {
        if UIApplication.shared.canOpenURL(url) {
          return(false, "\(urlScheme) URL scheme detected")
        }
      }
    }
    #endif
    return (true, "")
  }
  
  // "cydia://" URL scheme has been removed. Turns out there is app in the official App Store
  // that has the cydia:// URL scheme registered, so it may cause false positive
  // "activator://" URL scheme has been removed for the same reason.
    @MainActor private static func checkURLSchemes() -> CheckResult {
    let urlSchemes = [
      "undecimus://",
      "sileo://",
      "zbra://",
      "filza://"
    ]
    return canOpenUrlFromList(urlSchemes: urlSchemes)
  }
  
  private static func checkExistenceOfSuspiciousFiles() -> CheckResult {
    var paths = [
      "/var/mobile/Library/Preferences/ABPattern", // A-Bypass
      "/usr/lib/ABDYLD.dylib", // A-Bypass,
      "/usr/lib/ABSubLoader.dylib", // A-Bypass
      "/usr/sbin/frida-server", // frida
      "/etc/apt/sources.list.d/electra.list", // electra
      "/etc/apt/sources.list.d/sileo.sources", // electra
      "/.bootstrapped_electra", // electra
      "/usr/lib/libjailbreak.dylib", // electra
      "/jb/lzma", // electra
      "/.cydia_no_stash", // unc0ver
      "/.installed_unc0ver", // unc0ver
      "/jb/offsets.plist", // unc0ver
      "/usr/share/jailbreak/injectme.plist", // unc0ver
      "/etc/apt/undecimus/undecimus.list", // unc0ver
      "/var/lib/dpkg/info/mobilesubstrate.md5sums", // unc0ver
      "/Library/MobileSubstrate/MobileSubstrate.dylib",
      "/jb/jailbreakd.plist", // unc0ver
      "/jb/amfid_payload.dylib", // unc0ver
      "/jb/libjailbreak.dylib", // unc0ver
      "/usr/libexec/cydia/firmware.sh",
      "/var/lib/cydia",
      "/etc/apt",
      "/private/var/lib/apt",
      "/private/var/Users/",
      "/var/log/apt",
      "/Applications/Cydia.app",
      "/private/var/stash",
      "/private/var/lib/apt/",
      "/private/var/lib/cydia",
      "/private/var/cache/apt/",
      "/private/var/log/syslog",
      "/private/var/tmp/cydia.log",
      "/Applications/Icy.app",
      "/Applications/MxTube.app",
      "/Applications/RockApp.app",
      "/Applications/blackra1n.app",
      "/Applications/SBSettings.app",
      "/Applications/FakeCarrier.app",
      "/Applications/WinterBoard.app",
      "/Applications/IntelliScreen.app",
      "/private/var/mobile/Library/SBSettings/Themes",
      "/Library/MobileSubstrate/CydiaSubstrate.dylib",
      "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
      "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
      "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
      "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
      "/Applications/Sileo.app",
      "/var/binpack",
      "/Library/PreferenceBundles/LibertyPref.bundle",
      "/Library/PreferenceBundles/ShadowPreferences.bundle",
      "/Library/PreferenceBundles/ABypassPrefs.bundle",
      "/Library/PreferenceBundles/FlyJBPrefs.bundle",
      "/Library/PreferenceBundles/Cephei.bundle",
      "/Library/PreferenceBundles/SubstitutePrefs.bundle",
      "/Library/PreferenceBundles/libhbangprefs.bundle",
      "/usr/lib/libhooker.dylib",
      "/usr/lib/libsubstitute.dylib",
      "/usr/lib/substrate",
      "/usr/lib/TweakInject",
      "/var/binpack/Applications/loader.app", // checkra1n
      "/Applications/FlyJB.app", // Fly JB X
      "/Applications/Zebra.app", // Zebra
      "/Library/BawAppie/ABypass", // ABypass
      "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist", // SSL Killswitch
      "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist", // PreferenceLoader
      "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib", // PreferenceLoader
      "/Library/MobileSubstrate/DynamicLibraries", // DynamicLibraries directory in general
      "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"
    ]
    
    // These files can give false positive in the emulator
    if !NFSEmulatorChecker.amIRunInEmulator() {
      paths += [
        "/bin/bash",
        "/usr/sbin/sshd",
        "/usr/libexec/ssh-keysign",
        "/bin/sh",
        "/etc/ssh/sshd_config",
        "/usr/libexec/sftp-server",
        "/usr/bin/ssh"
      ]
    }
    
    for path in paths {
      if FileManager.default.fileExists(atPath: path) {
        return (false, "Suspicious file exists: \(path)")
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaStat(path: path) {
        return result
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaFOpen(
        path: path,
        mode: .readable
      ) {
        return result
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaAccess(
        path: path,
        mode: .readable
      ) {
        return result
      }
    }
    
    return (true, "")
  }
  
  private static func checkSuspiciousFilesCanBeOpened() -> CheckResult {
    var paths = [
      "/.installed_unc0ver",
      "/.bootstrapped_electra",
      "/Applications/Cydia.app",
      "/Library/MobileSubstrate/MobileSubstrate.dylib",
      "/etc/apt",
      "/var/log/apt"
    ]
    
    // These files can give false positive in the emulator
    if !NFSEmulatorChecker.amIRunInEmulator() {
      paths += [
        "/bin/bash",
        "/usr/sbin/sshd",
        "/usr/bin/ssh"
      ]
    }
    
    for path in paths {
      if FileManager.default.isReadableFile(atPath: path) {
        return (false, "Suspicious file can be opened: \(path)")
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaFOpen(
        path: path,
        mode: .writable
      ) {
        return result
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaAccess(
        path: path,
        mode: .writable
      ) {
        return result
      }
    }
    
    return (true, "")
  }
  
  private static func checkRestrictedDirectoriesWriteable() -> CheckResult {
    let paths = [
      "/",
      "/root/",
      "/private/",
      "/jb/"
    ]
    
    if FileChecker.checkRestrictedPathIsReadonlyViaStatvfs(path: "/") == false {
      return (false, "Restricted path '/' is not Read-Only")
    } else if FileChecker.checkRestrictedPathIsReadonlyViaStatfs(path: "/") == false {
      return (false, "Restricted path '/' is not Read-Only")
    } else if FileChecker.checkRestrictedPathIsReadonlyViaGetfsstat(name: "/") == false {
      return (false, "Restricted path '/' is not Read-Only")
    }
    
    // If library won't be able to write to any restricted directory the return(false, ...) is never reached
    // because of catch{} statement
    for path in paths {
      do {
        let pathWithSomeRandom = path + UUID().uuidString
        try "AmIJailbroken?".write(
          toFile: pathWithSomeRandom,
          atomically: true,
          encoding: String.Encoding.utf8
        )
        // clean if succesfully written
        try FileManager.default.removeItem(atPath: pathWithSomeRandom)
        return (false, "Wrote to restricted path: \(path)")
      } catch {}
    }
    
    return (true, "")
  }
  
  private static func checkFork() -> CheckResult {
    let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
    let forkPtr = dlsym(pointerToFork, "fork")
    typealias ForkType = @convention(c) () -> pid_t
    let fork = unsafeBitCast(forkPtr, to: ForkType.self)
    let forkResult = fork()
    
    if forkResult >= 0 {
      if forkResult > 0 {
        kill(forkResult, SIGTERM)
      }
      return (false, "Fork was able to create a new process (sandbox violation)")
    }
    
    return (true, "")
  }
  
  private static func checkSymbolicLinks() -> CheckResult {
    let paths = [
      "/var/lib/undecimus/apt", // unc0ver
      "/Applications",
      "/Library/Ringtones",
      "/Library/Wallpaper",
      "/usr/arm-apple-darwin9",
      "/usr/include",
      "/usr/libexec",
      "/usr/share"
    ]
    
    for path in paths {
      do {
        let result = try FileManager.default.destinationOfSymbolicLink(atPath: path)
        if !result.isEmpty {
          return (false, "Non standard symbolic link detected: \(path) points to \(result)")
        }
      } catch {}
    }
    
    return (true, "")
  }
  
  private static func checkDYLD() -> CheckResult {
    let suspiciousLibraries: Set<String> = [
      "systemhook.dylib", // Dopamine - hide jailbreak detection https://github.com/opa334/Dopamine/blob/dc1a1a3486bb5d74b8f2ea6ada782acdc2f34d0a/Application/Dopamine/Jailbreak/DOEnvironmentManager.m#L498
      "SubstrateLoader.dylib",
      "SSLKillSwitch2.dylib",
      "SSLKillSwitch.dylib",
      "MobileSubstrate.dylib",
      "TweakInject.dylib",
      "CydiaSubstrate",
      "cynject",
      "CustomWidgetIcons",
      "PreferenceLoader",
      "RocketBootstrap",
      "WeeLoader",
      "/.file", // HideJB (2.1.1) changes full paths of the suspicious libraries to "/.file"
      "libhooker",
      "SubstrateInserter",
      "SubstrateBootstrap",
      "ABypass",
      "FlyJB",
      "Substitute",
      "Cephei",
      "Electra",
      "AppSyncUnified-FrontBoard.dylib",
      "Shadow",
      "FridaGadget",
      "frida",
      "libcycript"
    ]
    
    for index in 0..<_dyld_image_count() {
      let imageName = String(cString: _dyld_get_image_name(index))
      
      // The fastest case insensitive contains check.
      for library in suspiciousLibraries where imageName.localizedCaseInsensitiveContains(library) {
        return (false, "Suspicious library loaded: \(imageName)")
      }
    }
    
    return (true, "")
  }
  
  private static func checkSuspiciousObjCClasses() -> CheckResult {
    if let shadowRulesetClass = objc_getClass("ShadowRuleset") as? NSObject.Type {
      let selector = Selector(("internalDictionary"))
      if class_getInstanceMethod(shadowRulesetClass, selector) != nil {
        return (false, "Shadow anti-anti-jailbreak detector detected :-)")
      }
    }
    return (true, "")
  }
}
// swiftlint:enable function_body_length type_body_length
