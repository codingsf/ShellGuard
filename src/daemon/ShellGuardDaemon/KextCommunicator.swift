import Foundation


/*
 * KextCommunications is responsible for communication to the kext.
 * KextCommunications is a Singleton class.
 *
 */
class KextCommunicator {
    
    let PROC            = 0
    let OPERATION       = 1
    let PATH            = 2
    let ROOT            = 3
    let PATH_WILDCARD   = 4
    let ACTION          = 5
    
    
    /* Socket used to connect to kext. */
    var g_socket: Int32 = -1
    
    static let sharedInstance = KextCommunicator()
    
    private init() {}
    
    /*
    * Connects and initializes socket used to communicate with kext.
    */
    func connectToKext() -> Bool {
        
        g_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        guard g_socket >= 0 else {
            print("Failed to open a kernel control socket")
            return false
        }
        
        let controlIdentifier = getControlIdentifier(g_socket)
        guard controlIdentifier > 0 else {
            print("Failed to get the control ID for the utun kernel control")
            close(g_socket)
            return false
        }
        
        // Connect the socket to the kernel control.
        var socketAddressControl = sockaddr_ctl(sc_len: UInt8(sizeof(sockaddr_ctl.self)), sc_family: UInt8(AF_SYSTEM), ss_sysaddr: UInt16(AF_SYS_CONTROL), sc_id: controlIdentifier, sc_unit: 0, sc_reserved: (0, 0, 0, 0, 0))
        
        let connectResult = withUnsafePointer(&socketAddressControl) {
            connect(g_socket, UnsafePointer<sockaddr>($0), socklen_t(sizeofValue(socketAddressControl)))
        }
        
        if let errorString = String(UTF8String: strerror(errno)) where connectResult < 0 {
            print("Failed to create a utun interface: \(errorString)")
            close(g_socket)
            return false
        }
        print("[INFO] Connected to socket: \(g_socket)")
        
        init_dispatch_queues(g_socket);
        
        print("[INFO] Connected to kernel!")
        
        return true
    }
    
    /*
    * Sends kernelspace stuff via Obj-C bridging to C/kext.
    */
    func prepAndSendToSocket(cmd: UInt32, pid: UInt32, procname: String) {
        _ = prepControlDataAndSend(Int32(g_socket), cmd, pid, procname, nil)
    }
    
    
    func sendListToKext(list: [Item], mode: Int32) {
        for item in list {
            print(item.toString())
            if mode == LOAD_WHITELIST {
                _ = prepControlDataAndSend(Int32(g_socket), UInt32(LOAD_WHITELIST), UINT32_MAX, "N/A", toEntryStruct(item.processName, item.shell))
            } else {
                _ = prepControlDataAndSend(Int32(g_socket), UInt32(LOAD_SHELLS), UINT32_MAX, "N/A", toEntryStruct("N/A", item.shell))
            }
        }
    }
    
    
    func printMessage(message: String) {
        let message_parts = message.componentsSeparatedByString(";")
        guard message_parts.count == 3 else {
            print("[ERROR] Incorrectly formatted message: \(message_parts)")
            return
        }
        print("[INFO] Kernel message: \(message_parts[PROC]) tried to \(message_parts[OPERATION]) on \(message_parts[PATH]) blocked. ")
    }
}


/* Functions in this class are callable from the C/Obj-C functions. */
@objc public class SwiftHelper : NSObject {
    
    let PROCNAME    = 0
    let SHELL       = 1
    
    let ENFORCING   = 4
    let COMPLAING   = 7
    
    let logger = Logger.sharedInstance

    @objc func receiveMessageFromKext(message: String, mode: Int) {
        let message_parts = message.componentsSeparatedByString(";")
        guard message_parts.count == 3 else {
            print("[ERROR] Incorrectly formatted message: \(message_parts)")
            return
        }
        print("[INFO] Kernel message: \(message_parts[PROCNAME]) tried to execute \(message_parts[SHELL]). ShellGuard blocked this. ")
        spawnNotification(message_parts, mode: mode);
    }
    
    func spawnNotification(message: [String], mode: Int) {
        var notificationMode: String
        switch (mode) {
            case COMPLAING:
                notificationMode = "Complaining:"
                break;
            case ENFORCING:
                notificationMode = "Blocking:"
            default:
                return
        }
        let notification = NSUserNotification()
        notification.title = "ShellGuard"
        let message = "\(notificationMode) \(message[PROCNAME]) executing \(message[SHELL]). \(message[PROCNAME]) may be malicious."
        notification.informativeText = message
        notification.soundName = nil
        NSUserNotificationCenter.defaultUserNotificationCenter().deliverNotification(notification)
        logger.log(message)
    }
}














