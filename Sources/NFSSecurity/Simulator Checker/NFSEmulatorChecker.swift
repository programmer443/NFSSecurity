import Foundation

internal class NFSEmulatorChecker {
  static func amIRunInEmulator() -> Bool {
    return checkCompile() || checkRuntime()
  }

  private static func checkRuntime() -> Bool {
    return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
  }

  private static func checkCompile() -> Bool {
#if targetEnvironment(simulator)
    return true
#else
    return false
#endif
  }
}
