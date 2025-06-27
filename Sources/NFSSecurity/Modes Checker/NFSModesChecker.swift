import Foundation

public final class NFSModesChecker {
  
    public static func amIInLockdownMode() -> Bool {
      UserDefaults.standard.bool(forKey: "LDMGlobalEnabled")
  }
}
