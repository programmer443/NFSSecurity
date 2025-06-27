import Foundation
import MachO

public final class NFSDebuggerDetectionController: ObservableObject {
    @Published var isDebuggerAttached: Bool = false
    
    init() {
        self.isDebuggerAttached = NFSDebuggerDetection.isDebuggerAttached()
    }
}

public enum NFSDebuggerDetection {
    
    public static func isDebuggerAttached() -> Bool {
        return checkPtrace()
        || checkSysctl()
        || detectSuspiciousProcesses()
        || isBeingDebugged()
        || isFridaRunning()
        || checkDYLD()
    }
    
    // Check if ptrace is being used to prevent debugging
    private static func checkPtrace() -> Bool {
        var name = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var info_size = MemoryLayout<kinfo_proc>.size
        let result = sysctl(&name, u_int(name.count), &info, &info_size, nil, 0)
        return result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    // Check sysctl for debugging flags
    private static func checkSysctl() -> Bool {
        var name = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var info_size = MemoryLayout<kinfo_proc>.size
        let result = sysctl(&name, u_int(name.count), &info, &info_size, nil, 0)
        return result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    // Detect suspicious processes (e.g., Frida)
    private static func detectSuspiciousProcesses() -> Bool {
        let suspiciousProcesses = ["frida-server", "frida", "frida-helper"]
        let taskList = getTaskList()
        for process in suspiciousProcesses {
            if taskList.contains(where: { $0.contains(process) }) {
                return true
            }
        }
        return false
    }
    
    // Get a list of running tasks
    private static func getTaskList() -> [String] {
        var processes: [String] = []

        // Set up the sysctl query
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        sysctl(&mib, u_int(mib.count), nil, &size, nil, 0)

        // Allocate memory for the process list
        let capacity = size / MemoryLayout<kinfo_proc>.stride
        var procList = [kinfo_proc](repeating: kinfo_proc(), count: capacity)

        // Retrieve the process list
        sysctl(&mib, u_int(mib.count), &procList, &size, nil, 0)

        // Extract process names from the process list
        for index in 0 ..< capacity {
            var proc = procList[index] // Make a mutable copy
            let name = withUnsafePointer(to: &proc.kp_proc.p_comm) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) { namePtr in
                    String(cString: namePtr)
                }
            }
            processes.append(name)
        }

        return processes
    }
    
    // Check if the app is being debugged using system functions
    private static func isBeingDebugged() -> Bool {
        var info = kinfo_proc()
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let sysctlResult = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        assert(sysctlResult == 0, "sysctl failed")
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    // checks if frida is unning
    private static func isFridaRunning() -> Bool {
        func swapBytesIfNeeded(port: in_port_t) -> in_port_t {
            let littleEndian = Int(OSHostByteOrder()) == OSLittleEndian
            return littleEndian ? _OSSwapInt16(port) : port
        }
        
        var serverAddress = sockaddr_in()
        serverAddress.sin_family = sa_family_t(AF_INET)
        serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1")
        serverAddress.sin_port = swapBytesIfNeeded(port: in_port_t(27042))
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        
        let result = withUnsafePointer(to: &serverAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }
        if result != -1 {
            return true
        }
        return false
    }
    
    private static func checkDYLD() -> Bool {
        let suspiciousLibraries = [
            "FridaGadget",
            "frida",
            "cynject",
            "libcycript"
        ]
        for libraryIndex in 0 ..< _dyld_image_count() {
            guard let loadedLibrary = String(validatingUTF8: _dyld_get_image_name(libraryIndex)) else { continue }
            for suspiciousLibrary in suspiciousLibraries {
                if loadedLibrary.lowercased().contains(suspiciousLibrary.lowercased()) {
                    return true
                }
            }
        }
        return false
    }
    
    static func amIDebugged() -> Bool {
    var kinfo = kinfo_proc()
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    var size = MemoryLayout<kinfo_proc>.stride
    let sysctlRet = sysctl(&mib, UInt32(mib.count), &kinfo, &size, nil, 0)
    
    if sysctlRet != 0 {
      print("❌ Error occured when calling sysctl(). The debugger check may not be reliable")
    }
    
    return (kinfo.kp_proc.p_flag & P_TRACED) != 0
  }
  
  static func denyDebugger() {
    // bind ptrace()
    let pointerToPtrace = UnsafeMutableRawPointer(bitPattern: -2)
    let ptracePtr = dlsym(pointerToPtrace, "ptrace")
    typealias PtraceType = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
    let ptrace = unsafeBitCast(ptracePtr, to: PtraceType.self)
    
    // PT_DENY_ATTACH == 31
    let ptraceRet = ptrace(31, 0, 0, 0)
    
    if ptraceRet != 0 {
      print("❌ Error occured when calling ptrace(). Denying debugger may not be reliable")
    }
  }
  
#if arch(arm64)
  static func hasBreakpointAt(
    _ functionAddr: UnsafeRawPointer,
    functionSize: vm_size_t?
  ) -> Bool {
    let funcAddr = vm_address_t(UInt(bitPattern: functionAddr))
    
    var vmStart: vm_address_t = funcAddr
    var vmSize: vm_size_t = 0
    let vmRegionInfo = UnsafeMutablePointer<Int32>.allocate(
      capacity: MemoryLayout<vm_region_basic_info_64>.size/4
    )
    
    defer {
      vmRegionInfo.deallocate()
    }
    
    var vmRegionInfoCount: mach_msg_type_number_t = mach_msg_type_number_t(VM_REGION_BASIC_INFO_64)
    var objectName: mach_port_t = 0
    
    let ret = vm_region_64(
      mach_task_self_, &vmStart,
      &vmSize, VM_REGION_BASIC_INFO_64,
      vmRegionInfo, &vmRegionInfoCount,
      &objectName
    )
    
    if ret != KERN_SUCCESS {
      return false
    }
    
    let vmRegion = vmRegionInfo.withMemoryRebound(
      to: vm_region_basic_info_64.self, capacity: 1, { $0 }
    )
    
    if vmRegion.pointee.protection == (VM_PROT_READ | VM_PROT_EXECUTE) {
      let armBreakpointOpcode = 0xe7ffdefe
      let arm64BreakpointOpcode = 0xd4200000
      let instructionBegin = functionAddr.bindMemory(to: UInt32.self, capacity: 1)
      var judgeSize = (vmSize - (funcAddr - vmStart))
      if let size = functionSize, size < judgeSize {
        judgeSize = size
      }
      
      for valueToOffset in 0..<(judgeSize / 4) {
        if (instructionBegin.advanced(
          by: Int(valueToOffset)
        ).pointee == armBreakpointOpcode) || (instructionBegin.advanced(
          by: Int(valueToOffset)
        ).pointee == arm64BreakpointOpcode) {
          return true
        }
      }
    }
    
    return false
  }
  
  static func hasWatchpoint() -> Bool {
    var threads: thread_act_array_t?
    var threadCount: mach_msg_type_number_t = 0
    var hasWatchpoint = false
    
    if task_threads(mach_task_self_, &threads, &threadCount) == KERN_SUCCESS {
      var threadStat = arm_debug_state64_t()
      let capacity = MemoryLayout<arm_debug_state64_t>.size/MemoryLayout<natural_t>.size
      
      let threadStatPointer = withUnsafeMutablePointer(to: &threadStat, {
        $0.withMemoryRebound(to: natural_t.self, capacity: capacity, { $0 })
      })
      
      var count = mach_msg_type_number_t(
        MemoryLayout<arm_debug_state64_t>.size/MemoryLayout<UInt32>.size
      )
      
      guard let threads = threads else {
        return false
      }
      
      for threadIndex in 0..<threadCount where thread_get_state(
        threads[Int(threadIndex)],
        ARM_DEBUG_STATE64,
        threadStatPointer,
        &count
      ) == KERN_SUCCESS {
        hasWatchpoint = threadStatPointer.withMemoryRebound(
          to: arm_debug_state64_t.self, capacity: 1, { $0 }
        ).pointee.__wvr.0 != 0
        if hasWatchpoint { break }
      }
      
      vm_deallocate(
        mach_task_self_,
        UInt(bitPattern: threads),
        vm_size_t(threadCount * UInt32(MemoryLayout<thread_act_t>.size))
      )
    }
    
    return hasWatchpoint
  }
#endif
  
  static func isParentPidUnexpected() -> Bool {
    let parentPid: pid_t = getppid()
    
    return parentPid != 1 // LaunchD is pid 1
  }
}
