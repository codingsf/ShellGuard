import Cocoa

class StatusMenuController: NSObject {
    
    /* State the application can be in. */
    enum State: UInt32 {
        case LOAD_WHITELIST     = 1
        case LOAD_SHELLS        = 2
        case ENFORCING          = 4
        case ENFORCING_OFF      = 5
        case COMPLAINING        = 7
        case COMPLAINING_OFF    = 8
    }
    
    let POLICY_FILE_LOCATION = "/Users/Shared/SG_config.json"
    
    let DARK        = true
    let ENABLED     = true
    let LIGHT       = false
    let DISABLED    = false
    
    let loader = ConfigLoader.sharedInstance
    let kextCommunicate = KextCommunicator.sharedInstance
    let secureStore = KeychainStore.sharedInstance
    
    let kextCommunicationsQueue = dispatch_queue_create("KextCommunications", nil)
    
    var connectedToKext = false
    var currentMode: UInt32 = 4
    var active = false

    /*
     * UI crap for the menuItems
     */
    let statusItem = NSStatusBar.systemStatusBar().statusItemWithLength(NSVariableStatusItemLength)
    var statusBarIcon = NSImage()
    var statusMenuItem: NSMenuItem!

    @IBOutlet weak var statusMenu: NSMenu!
    @IBOutlet weak var modeMenu: NSMenu!
    
    @IBAction func enableClicked(sender: NSMenuItem) {
        control((currentMode, true))
    }
    @IBAction func disableClicked(sender: NSMenuItem) {
        control((currentMode, false))
    }
    @IBAction func complainClicked(sender: NSMenuItem) {
        actionCommonToAllMenus(sender)
        control((State.COMPLAINING.rawValue, true))
    }
    @IBAction func enforceClicked(sender: NSMenuItem) {
        actionCommonToAllMenus(sender)
        control((State.ENFORCING.rawValue, true))
    }
    @IBAction func aboutClicked(sender: NSMenuItem) {
        NSApplication.sharedApplication().terminate(self)
    }
    
    func actionCommonToAllMenus(current: NSMenuItem) {
        for menuItem in modeMenu.itemArray {
            menuItem.state = NSOffState
        }
        current.state = NSOnState
    }
    
    
    /* 
     * Application logic starts here.
     */
    override func awakeFromNib() {
        statusItem.menu = statusMenu
        setStatusIcon((DARK, DISABLED))

        print("\n\t[ Swift OS X ShellGuard Daemon ] \n\n")
        print("[INFO] Connecting to kernel...")
        connectKext()
        connectedToKext = true
        /* Restore previously saved state from Keychain. */
        restoreSavedState()
        control((currentMode, connectedToKext))
    }
    
    
    /*
     * Sets the proper mode and does house/state keeping.
     */
    func control(conf: (mode: UInt32, status: Bool)) {
        if !connectedToKext {
            //connectKext()
            sleep(3)
            if !connectedToKext {
                notify("Could not change mode. Not connected to kext. Please check if the kext is loaded.")
                return
            }
        }
        switch conf {
            case (State.COMPLAINING.rawValue, true):
                enableMode(State.COMPLAINING.rawValue)
                setStatusIcon((DARK, ENABLED))
                active = true
                saveState(State.COMPLAINING.rawValue)
                break
            case (State.COMPLAINING.rawValue, false):
                disableMode(State.COMPLAINING_OFF.rawValue)
                setStatusIcon((DARK, DISABLED))
                active = false
                saveState(State.COMPLAINING.rawValue)
                break
            case (State.ENFORCING.rawValue, true):
                enableMode(State.ENFORCING.rawValue)
                setStatusIcon((DARK, ENABLED))
                active = true
                saveState(State.ENFORCING.rawValue)
                break
            case (State.ENFORCING.rawValue, false):
                disableMode(State.ENFORCING_OFF.rawValue)
                setStatusIcon((DARK, DISABLED))
                active = false
                saveState(State.ENFORCING.rawValue)
                break
            default:
                /* do nothing? */
                return
        }
    }
    
    func enableMode(mode: UInt32) {
        loader.loadConfigFile(POLICY_FILE_LOCATION)
        kextCommunicate.sendListToKext(loader.getWhitelist(), mode: LOAD_WHITELIST)
        kextCommunicate.sendListToKext(loader.getShellList(), mode: LOAD_SHELLS)
        kextCommunicate.prepAndSendToSocket(mode, pid: UINT32_MAX, procname: "N/A")
    }
    
    func disableMode(mode: UInt32) {
        loader.emptyWhitelist()
        self.kextCommunicate.prepAndSendToSocket(mode, pid: UINT32_MAX, procname: "N/A")
    }
    
    func setStatusIcon(conf: (dark: Bool, enabled: Bool)) {
        switch conf {
            case (DARK, ENABLED):
                statusBarIcon = NSImage(named: "darkStatusIconEnabled")!
                statusBarIcon.template = true
                if let statusMenuItem = statusMenu.itemWithTag(0) {
                    statusMenuItem.title = "Status: Enabled"
                    
                }
                break
            case (DARK, DISABLED):
                statusBarIcon = NSImage(named: "darkStatusIconDisabled")!
                statusBarIcon.template = true
                if let statusMenuItem = statusMenu.itemWithTag(0) {
                    statusMenuItem.title = "Status: Disabled"
                    
                }
                break
            case (LIGHT, ENABLED):
                statusBarIcon = NSImage(named: "lightStatusIconDisabled")!
                statusBarIcon.template = false
                if let statusMenuItem = statusMenu.itemWithTag(0) {
                    statusMenuItem.title = "Status: Enabled"
                    
                }
                break
            case (LIGHT, DISABLED):
                statusBarIcon = NSImage(named: "lightStatusIconDisabled")!
                statusBarIcon.template = false
                if let statusMenuItem = statusMenu.itemWithTag(0) {
                    statusMenuItem.title = "Status: Disabled"
                    
                }
                break
            default:
                // this cannot happen..
                break
        }
        statusItem.image = statusBarIcon
    }
    
    func saveState(state: UInt32) {
        currentMode = state
        secureStore.set(String(state), forKey: "ShellGuardState")
    }
    
    func restoreSavedState() {
        if let stateStr = secureStore.get("ShellGuardState") {
            
            currentMode = UInt32(stateStr)!
        } else {
            // always fall back to enforcing mode.
            print("[ERROR] Falling down to ENFORCING")
            currentMode = State.ENFORCING.rawValue
        }
        if let modeMenuItem = self.modeMenu.itemWithTag(Int(currentMode)) {
            modeMenuItem.state = NSOnState
        }
    }
        
    func notify(message: String) {
        let notification = NSUserNotification()
        notification.title = "ShellGuard"
        notification.informativeText = message
        notification.soundName = nil
        NSUserNotificationCenter.defaultUserNotificationCenter().deliverNotification(notification)
    }
    /*
    * Connect to the kext, using a GCD queue (thread).
    * If we cannot connect to the Kext, we will hang in this while loop...
    */
    func connectKext() {
        // Dispath to the newly created quese. GCD take the responsibility for most things.
        dispatch_async(kextCommunicationsQueue) {
            self.connectedToKext = self.kextCommunicate.connectToKext()
            while (!self.connectedToKext) {
                print("[ERROR] Can't connect to kernel control socket! Trying again in 30 seconds")
                sleep(30)
                self.connectedToKext = self.kextCommunicate.connectToKext()
            }
            dispatch_async(dispatch_get_main_queue()) {
                self.setStatusIcon((self.DARK, self.ENABLED))
            }
        }
    }
}

/* We can use some more Stringness. */
extension String {
    func replace(string:String, replacement:String) -> String {
        return self.stringByReplacingOccurrencesOfString(string, withString: replacement, options: NSStringCompareOptions.LiteralSearch, range: nil)
    }
    
    /* If used on a path containing spaces, this function could have negative effects. Use trim() */
    func removeWhitespace() -> String {
        return self.replace(" ", replacement: "")
    }
    
    /* Still need space for '\0' in C char buffer, so not <=  */
    func isSmallerThan(i: Int) -> Bool {
        return self.characters.count < i
    }
    
    func contains(find: String) -> Bool {
        return self.rangeOfString(find) != nil
    }
    
    /* Removed leading and trailing white spaces. */
    func trim() -> String {
        return self.stringByTrimmingCharactersInSet(NSCharacterSet.whitespaceCharacterSet())
    }
}



