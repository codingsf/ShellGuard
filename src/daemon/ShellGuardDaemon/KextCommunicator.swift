import Foundation


/*
 * KextCommunications is responsible for communication to the kext.
 * KextCommunications is a Singleton class.
 *
 */
class KextCommunicator {

    
    /* Socket used to connect to kext. */
    var g_socket: Int32 = -1
    
    static let sharedInstance = KextCommunicator()
    
    
    /*
    * Connects and initializes socket used to communicate with kext.
    */
    func connectToKext() -> Bool {
        
        g_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        guard g_socket >= 0 else {
            print("Failed to open a kernel control socket")
            return false
        }
        
        let controlIdentifier = get_control_identifier(g_socket)
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
        
        if let errorString = String(validatingUTF8: strerror(errno)) where connectResult < 0 {
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
     * Sends configs for kext via Obj-C bridging to C/kext.
     */
    func setKextMode(_ cmd: UInt32) {
        _ = send_to_kernel(Int32(g_socket), cmd, nil)
    }
    
    
    func sendListToKext(_ list: [Item], mode: Int32) {
        for item in list {
            print(item.toString())
            _ = send_to_kernel(Int32(g_socket), UInt32(mode), toEntryStruct(item.processName, item.shell))
        }
    }
}


/* Functions in this class are callable from the C/Obj-C functions. */
@objc public class SwiftHelper : NSObject {
    
    let PROCNAME    = 0
    let SHELL       = 1
    
    let logger = Logger.sharedInstance

    @objc func receiveMessageFromKext(_ message: String, mode: Int, pid: Int, ppid: Int) {
        //print("Message: \(message)")
        let message_parts = message.components(separatedBy: ";")
        guard message_parts.count == 3 else {
            print("[ERROR] Incorrectly formatted message: \(message_parts)")
            return
        }
        switch (Int32(mode)) {
            case ENFORCING:
                print("[!!] \(message_parts[PROCNAME]) (\(ppid)) tried to execute \(message_parts[SHELL]) (\(pid)). ShellGuard blocked this.")
                break
            case COMPLAINING:
                print("[!]  \(message_parts[PROCNAME]) (\(ppid)) tried to execute \(message_parts[SHELL]) (\(pid)). ShellGuard just complains.")
                break
            default:
                return
        }
        spawnNotification(message_parts, mode: mode, pid: pid, ppid: ppid);
    }
    
    func spawnNotification(_ m: [String], mode: Int, pid: Int, ppid: Int) {
        var notificationMode: String
        let notification = NSUserNotification()
        notification.title = "ShellGuard"
        var message = ""
        switch (Int32(mode)) {
            case COMPLAINING:
                notificationMode = "Complaining:"
                break
            case ENFORCING:
                notificationMode = "Blocking:"
                break
            default:
                return
        }
        message = "\(notificationMode) \(m[PROCNAME]) (\(ppid)) executing \(m[SHELL]) (\(pid)). \(m[PROCNAME]) (\(ppid)) may be malicious."
        notification.informativeText = message
        notification.soundName = nil
        NSUserNotificationCenter.default().deliver(notification)
        _ = logger.log(message)
    }
}














