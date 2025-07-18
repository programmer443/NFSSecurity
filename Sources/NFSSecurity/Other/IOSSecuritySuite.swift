import Foundation
import MachO

/// Main class that encompasses library functionalities
@available(iOSApplicationExtension, unavailable)
public class IOSSecuritySuite {
  /// This type method is used to determine the true/false jailbreak status
  ///
  /// Usage example
  /// ```swift
  /// let isDeviceJailbroken: Bool = IOSSecuritySuite.amIJailbroken()
  /// ```
  ///
  /// - Returns: Bool indicating if the device has jailbreak (true) or not (false)
    @MainActor public static func amIJailbroken() -> Bool {
    return JailbreakChecker.amIJailbroken()
  }
  
  /// This type method is used to determine the jailbreak status with a message which jailbreak indicator was detected
  ///
  /// Usage example
  /// ```swift
  /// let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailMessage()
  /// if jailbreakStatus.jailbroken {
  ///   print("This device is jailbroken")
  ///   print("Because: \(jailbreakStatus.failMessage)")
  /// } else {
  ///   print("This device is not jailbroken")
  /// }
  /// ```
  ///
  /// - Returns: Tuple with with the jailbreak status (Bool) and failMessage (String)
    @MainActor public static func amIJailbrokenWithFailMessage() -> (jailbroken: Bool, failMessage: String) {
    return JailbreakChecker.amIJailbrokenWithFailMessage()
  }
  
  /// This type method is used to determine the jailbreak status with a list of failed checks
  ///
  /// Usage example
  /// ```swift
  /// let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
  /// if jailbreakStatus.jailbroken {
  ///   print("This device is jailbroken")
  ///   print("The following checks failed: \(jailbreakStatus.failedChecks)")
  /// }
  /// ```
  ///
  /// - Returns: Tuple with with the jailbreak status (Bool) and a list of ``FailedCheckType``
    @MainActor public static func amIJailbrokenWithFailedChecks() -> (jailbroken: Bool,
                                                         failedChecks: [FailedCheckType]) {
    return JailbreakChecker.amIJailbrokenWithFailedChecks()
  }
  
  /// This type method is used to determine if application is run in emulator
  ///
  /// Usage example
  /// ```swift
  /// let runInEmulator: Bool = IOSSecuritySuite.amIRunInEmulator()
  /// ```
  /// - Returns: Bool indicating if the device is an emulator (true) or not (false)
  public static func amIRunInEmulator() -> Bool {
    return NFSEmulatorChecker.amIRunInEmulator()
  }
  
  /// This type method is used to determine if application is being debugged
  ///
  /// Usage example
  /// ```swift
  /// let amIDebugged: Bool = IOSSecuritySuite.amIDebugged()
  /// ```
  /// - Returns: Bool indicating if the device is being debugged (true) or not (false)
  public static func amIDebugged() -> Bool {
    return NFSDebuggerDetection.amIDebugged()
  }
  
  /// This type method is used to deny debugger and improve the application resillency
  ///
  /// Usage example
  /// ```swift
  /// IOSSecuritySuite.denyDebugger()
  /// ```
  public static func denyDebugger() {
    return NFSDebuggerDetection.denyDebugger()
  }
  
  /// This method is used to determine if application was launched by something
  /// other than LaunchD (i.e. the app was launched by a debugger)
  ///
  /// Usage example
  /// ```swift
  /// let isNotLaunchD: Bool = IOSSecuritySuite.isParentPidUnexpected()
  /// ```
  /// - Returns: Bool indicating if application was launched by something other than LaunchD (true) or not (false)
  public static func isParentPidUnexpected() -> Bool {
    return NFSDebuggerDetection.isParentPidUnexpected()
  }
  
  /// This type method is used to determine if application has been tampered with
  ///
  /// Usage example
  /// ```swift
  /// if IOSSecuritySuite.amITampered(
  ///   [.bundleID("biz.securing.FrameworkClientApp"),
  ///    .mobileProvision("your-mobile-provision-sha256-value")]
  /// ).result {
  ///   print("I have been Tampered.")
  /// } else {
  ///   print("I have not been Tampered.")
  /// }
  /// ```
  ///
  /// - Parameter checks: The file Integrity checks you want
  /// - Returns: The file Integrity checker result
  public static func amITampered(_ checks: [FileIntegrityCheck]) -> FileIntegrityCheckResult {
    return NFSIntegrityChecker.amITampered(checks)
  }
  
  /// This type method is used to determine if there are any popular reverse engineering tools installed on the device
  ///
  /// Usage example
  /// ```swift
  /// let amIReverseEngineered: Bool = IOSSecuritySuite.amIReverseEngineered()
  /// ```
  /// - Returns: Bool indicating if device has reverse engineering tools (true) or not (false)
  public static func amIReverseEngineered() -> Bool {
    return NFSReverseEngineeringToolsChecker.amIReverseEngineered()
  }
  
  /// This type method is used to determine the reverse engineered status with a list of failed checks
  ///
  /// Usage example
  /// ```swift
  /// let reStatus = IOSSecuritySuite.amIReverseEngineeredWithFailedChecks()
  /// if reStatus.reverseEngineered {
  ///   print("This device has evidence of reverse engineering")
  ///   print("The following checks failed: \(reStatus.failedChecks)")
  /// }
  /// ```
  ///
  /// - Returns: Tuple with with the reverse engineered status (Bool) and a list of ``FailedCheckType``
  public static func amIReverseEngineeredWithFailedChecks() -> (reverseEngineered: Bool,
                                                                failedChecks: [FailedCheckType]) {
    return NFSReverseEngineeringToolsChecker.amIReverseEngineeredWithFailedChecks()
  }
  
  /// This type method is used to determine if `objc call` has been RuntimeHooked by for example `Flex`
  ///
  /// Usage example
  /// ```swift
  /// class SomeClass {
  ///   @objc dynamic func someFunction() { ... }
  /// }
  ///
  /// let dylds = ["IOSSecuritySuite", ...]
  ///
  /// let amIRuntimeHook: Bool = amIRuntimeHook(
  ///   dyldWhiteList: dylds,
  ///   detectionClass: SomeClass.self,
  ///   selector: #selector(SomeClass.someFunction),
  ///   isClassMethod: false
  ///  )
  /// ```
  ///
  /// - Returns: Bool indicating if the method is being hooked (true) or not (false)
  @available(
    *, deprecated,
     renamed: "amIRuntimeHooked(dyldAllowList:detectionClass:selector:isClassMethod:)"
  )
  public static func amIRuntimeHooked(
    dyldWhiteList: [String],
    detectionClass: AnyClass,
    selector: Selector,
    isClassMethod: Bool
  ) -> Bool {
    return RuntimeHookChecker.amIRuntimeHook(
      dyldAllowList: dyldWhiteList,
      detectionClass: detectionClass,
      selector: selector,
      isClassMethod: isClassMethod
    )
  }
  
  /// This type method is used to determine if `objc call` has been RuntimeHooked by for example `Flex`
  ///
  /// Usage example
  /// ```swift
  /// class SomeClass {
  ///   @objc dynamic func someFunction() { ... }
  /// }
  ///
  /// let dylds = ["IOSSecuritySuite", ...]
  ///
  /// let amIRuntimeHook: Bool = amIRuntimeHook(
  ///   dyldAllowList: dylds,
  ///   detectionClass: SomeClass.self,
  ///   selector: #selector(SomeClass.someFunction),
  ///   isClassMethod: false
  ///  )
  /// ```
  ///
  /// - Returns: Bool indicating if the method is being hooked (true) or not (false)
  public static func amIRuntimeHooked(
    dyldAllowList: [String],
    detectionClass: AnyClass,
    selector: Selector,
    isClassMethod: Bool
  ) -> Bool {
    return RuntimeHookChecker.amIRuntimeHook(
      dyldAllowList: dyldAllowList,
      detectionClass: detectionClass,
      selector: selector,
      isClassMethod: isClassMethod
    )
  }
  
  /// This type method is used to determine if  HTTP proxy was set in the iOS Settings.
  ///
  /// Usage example
  /// ```swift
  /// let amIProxied: Bool = IOSSecuritySuite.amIProxied()
  /// ```
  /// - Returns: Bool indicating if the device has a proxy setted (true) or not (false)
  public static func amIProxied() -> Bool {
    return ProxyChecker.amIProxied()
  }
  
  /// This type method is used to determine if the iDevice has lockdown mode turned on.
  ///
  /// Usage example
  /// ```swift
  /// let amIInLockdownMode: Bool = IOSSecuritySuite.amIInLockdownMode()
  /// ```
  /// - Returns: Bool indicating if the device has lockdown mode turned on (true) or not (false)
  @available(iOS 16, *)
  public static func amIInLockdownMode() -> Bool {
    return NFSModesChecker.amIInLockdownMode()
  }
}

#if arch(arm64)
@available(iOSApplicationExtension, unavailable)
public extension IOSSecuritySuite {
  /// This type method is used to determine if `function_address` has been hooked by `MSHook`
  ///
  /// Usage example
  /// ```swift
  /// func denyDebugger() { ... }
  ///
  /// typealias FunctionType = @convention(thin) ()->()
  ///
  /// let func_denyDebugger: FunctionType = denyDebugger // `: FunctionType` is must
  /// let func_addr = unsafeBitCast(func_denyDebugger, to: UnsafeMutableRawPointer.self)
  /// let amIMSHookFunction: Bool = amIMSHookFunction(func_addr)
  /// ```
  /// - Returns: Bool indicating if the function has been hooked (true) or not (false)
  static func amIMSHooked(_ functionAddress: UnsafeMutableRawPointer) -> Bool {
    return MSHookFunctionChecker.amIMSHooked(functionAddress)
  }
  
  /// This type method is used to get original `function_address` which has been hooked by  `MSHook`
  ///
  /// Usage example
  /// ```swift
  /// func denyDebugger(value: Int) { ... }
  ///
  /// typealias FunctionType = @convention(thin) (Int)->()
  ///
  /// let funcDenyDebugger: FunctionType = denyDebugger
  /// let funcAddr = unsafeBitCast(funcDenyDebugger, to: UnsafeMutableRawPointer.self)
  ///
  /// if let originalDenyDebugger = denyMSHook(funcAddr) {
  /// // Call orignal function with 1337 as Int argument
  ///   unsafeBitCast(originalDenyDebugger, to: FunctionType.self)(1337)
  /// } else {
  ///   denyDebugger()
  /// }
  /// ```
  static func denyMSHook(_ functionAddress: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
    return MSHookFunctionChecker.denyMSHook(functionAddress)
  }
  
  /// This type method is used to rebind `symbol` which has been hooked by `fishhook`
  ///
  /// Usage example
  /// ```swift
  /// denySymbolHook("$s10Foundation5NSLogyySS_s7CVarArg_pdtF") // Foudation's NSlog of Swift
  /// NSLog("Hello Symbol Hook")
  ///
  /// denySymbolHook("abort")
  /// abort()
  /// ```
  static func denySymbolHook(_ symbol: String) {
    FishHookChecker.denyFishHook(symbol)
  }
  
  /// This type method is used to rebind `symbol` which has been hooked  at one of image by `fishhook`
  ///
  /// Usage example
  /// ```
  /// for i in 0..<_dyld_image_count() {
  ///   if let imageName = _dyld_get_image_name(i) {
  ///     let name = String(cString: imageName)
  ///     if name.contains("IOSSecuritySuite"), let image = _dyld_get_image_header(i) {
  ///       denySymbolHook("dlsym", at: image, imageSlide: _dyld_get_image_vmaddr_slide(i))
  ///       break
  ///     }
  ///   }
  /// }
  /// ```
  static func denySymbolHook(
    _ symbol: String,
    at image: UnsafePointer<mach_header>,
    imageSlide slide: Int
  ) {
    FishHookChecker.denyFishHook(symbol, at: image, imageSlide: slide)
  }
  
  /// This type method is used to get the SHA256 hash value of the executable file in a specified image
  ///
  /// - Attention: **Dylib only.** This means you should set Mach-O type as `Dynamic Library` in your *Build Settings*.
  ///
  /// Calculate the hash value of the `__TEXT.__text` data of the specified image Mach-O file.
  ///
  /// Usage example
  /// ```swift
  /// // Manually verify SHA256 hash value of a loaded dylib
  /// if let hashValue = IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")),
  ///   hashValue == "6d8d460b9a4ee6c0f378e30f137cebaf2ce12bf31a2eef3729c36889158aa7fc" {
  ///     print("I have not been Tampered.")
  /// } else {
  ///   print("I have been Tampered.")
  /// }
  /// ```
  ///
  /// - Parameter target: The target image
  /// - Returns: A hash value of the executable file.
  static func getMachOFileHashValue(_ target: IntegrityCheckerImageTarget = .default) -> String? {
    return NFSIntegrityChecker.getMachOFileHashValue(target)
  }
  
  /// This type method is used to find all loaded dylibs in the specified image
  ///
  /// - Attention: **Dylib only.** This means you should set Mach-O type as `Dynamic Library` in your /*Build Settings*.
  ///
  /// Usage example
  /// ```swift
  /// if let loadedDylib = IOSSecuritySuite.findLoadedDylibs() {
  ///   print("Loaded dylibs: \(loadedDylib)")
  /// }
  /// ```
  ///
  /// - Parameter target: The target image
  /// - Returns: An Array with all loaded dylib names
  static func findLoadedDylibs(_ target: IntegrityCheckerImageTarget = .default) -> [String]? {
    return NFSIntegrityChecker.findLoadedDylibs(target)
  }
  
  /// This type method is used to determine if there are any breakpoints at the function
  ///
  /// Usage example
  /// ```swift
  /// func denyDebugger() {
  ///   // add a breakpoint at here to test
  /// }
  ///
  /// typealias FunctionType = @convention(thin) ()->()
  ///
  /// let func_denyDebugger: FunctionType = denyDebugger   // `: FunctionType` is a must
  /// let func_addr = unsafeBitCast(func_denyDebugger, to: UnsafeMutableRawPointer.self)
  /// let hasBreakpoint: Bool = IOSSecuritySuite.hasBreakpointAt(func_addr, functionSize: nil)
  /// ```
  /// - Returns: Bool indicating if the function has a breakpoint (true) or not (false)
  static func hasBreakpointAt(_ functionAddr: UnsafeRawPointer, functionSize: vm_size_t?) -> Bool {
    return NFSDebuggerDetection.hasBreakpointAt(functionAddr, functionSize: functionSize)
  }
  
  /// This type method is used to detect if a watchpoint is being used.
  /// A watchpoint is a type of breakpoint that 'watches' an area of memory associated with a data item.
  ///
  /// Usage example
  /// ```swift
  /// // Set a breakpoint at the testWatchpoint function
  /// func testWatchpoint() -> Bool{
  ///   // lldb: watchpoint set expression ptr
  ///   var ptr = malloc(9)
  ///   // lldb: watchpoint set variable count
  ///   var count = 3
  ///   return IOSSecuritySuite.hasWatchpoint()
  /// }
  /// ```
  /// - Returns: Bool indicating if has a watchpoint setted (true) or not (false)
  static func hasWatchpoint() -> Bool {
    return NFSDebuggerDetection.hasWatchpoint()
  }
}
#endif
// swiftlint:enable inclusive_language
