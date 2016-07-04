import Cocoa

class StatusMenuController: NSObject {
    
    /* State the application can be in. */
    enum State: UInt32 {
        case load_WHITELIST     = 1
        case load_SHELLS        = 2
        case reset_LISTS        = 3
        case enforcing          = 4
        case enforcing_OFF      = 5
        case complaining        = 7
        case complaining_OFF    = 8
    }
    
    let POLICY_FILE_LOCATION = "/Users/Shared/SG_config.json"
    
    let DARK        = true
    let ENABLED     = true
    let LIGHT       = false
    let DISABLED    = false
    
    let loader = ConfigLoader.sharedInstance
    let kextCommunicate = KextCommunicator.sharedInstance
    let secureStore = KeychainStore.sharedInstance
    
    let kextCommunicationsQueue = DispatchQueue(label: "KextCommunications", attributes: [])
    
    var connectedToKext = false
    var currentMode: UInt32 = 4
    var active = false

    /*
     * UI crap for the menuItems
     */
    let statusItem = NSStatusBar.system().statusItem(withLength: NSVariableStatusItemLength)
    var statusBarIcon = NSImage()
    var statusMenuItem: NSMenuItem!

    @IBOutlet weak var statusMenu: NSMenu!
    @IBOutlet weak var modeMenu: NSMenu!
    
    @IBAction func enableClicked(_ sender: NSMenuItem) {
        control((currentMode, true))
    }
    @IBAction func disableClicked(_ sender: NSMenuItem) {
        control((currentMode, false))
    }
    @IBAction func complainClicked(_ sender: NSMenuItem) {
        actionCommonToAllMenus(sender)
        control((State.complaining.rawValue, true))
    }
    @IBAction func enforceClicked(_ sender: NSMenuItem) {
        actionCommonToAllMenus(sender)
        control((State.enforcing.rawValue, true))
    }
    @IBAction func aboutClicked(_ sender: NSMenuItem) {
        NSApplication.shared().terminate(self)
    }
    
    func actionCommonToAllMenus(_ current: NSMenuItem) {
        for menuItem in modeMenu.items {
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
    func control(_ conf: (mode: UInt32, status: Bool)) {
        if !connectedToKext {
            //connectKext()
            sleep(3)
            if !connectedToKext {
                notify("Could not change mode. Not connected to kext. Please check if the kext is loaded.")
                return
            }
        }
        switch conf {
            case (State.complaining.rawValue, true):
                enableMode(State.complaining.rawValue)
                setStatusIcon((DARK, ENABLED))
                active = true
                saveState(State.complaining.rawValue)
                break
            case (State.complaining.rawValue, false):
                disableMode(State.complaining_OFF.rawValue)
                setStatusIcon((DARK, DISABLED))
                active = false
                saveState(State.complaining.rawValue)
                break
            case (State.enforcing.rawValue, true):
                enableMode(State.enforcing.rawValue)
                setStatusIcon((DARK, ENABLED))
                active = true
                saveState(State.enforcing.rawValue)
                break
            case (State.enforcing.rawValue, false):
                disableMode(State.enforcing_OFF.rawValue)
                setStatusIcon((DARK, DISABLED))
                active = false
                saveState(State.enforcing.rawValue)
                break
            default:
                /* do nothing? */
                return
        }
    }
    
    func enableMode(_ mode: UInt32) {
        loader.loadConfigFile(POLICY_FILE_LOCATION)
        kextCommunicate.setKextMode(UInt32(RESET_LISTS))
        kextCommunicate.sendListToKext(loader.getWhitelist(), mode: LOAD_WHITELIST)
        kextCommunicate.sendListToKext(loader.getShellList(), mode: LOAD_SHELLS)
        kextCommunicate.setKextMode(mode)
    }
    
    func disableMode(_ mode: UInt32) {
        loader.emptyWhitelist()
        self.kextCommunicate.setKextMode(mode)
    }
    
    func setStatusIcon(_ conf: (dark: Bool, enabled: Bool)) {
        switch conf {
            case (DARK, ENABLED):
                statusBarIcon = NSImage(named: "darkStatusIconEnabled")!
                statusBarIcon.isTemplate = true
                if let statusMenuItem = statusMenu.item(withTag: 0) {
                    statusMenuItem.title = "Status: Enabled"
                    
                }
                break
            case (DARK, DISABLED):
                statusBarIcon = NSImage(named: "darkStatusIconDisabled")!
                statusBarIcon.isTemplate = true
                if let statusMenuItem = statusMenu.item(withTag: 0) {
                    statusMenuItem.title = "Status: Disabled"
                    
                }
                break
            case (LIGHT, ENABLED):
                statusBarIcon = NSImage(named: "lightStatusIconDisabled")!
                statusBarIcon.isTemplate = false
                if let statusMenuItem = statusMenu.item(withTag: 0) {
                    statusMenuItem.title = "Status: Enabled"
                    
                }
                break
            case (LIGHT, DISABLED):
                statusBarIcon = NSImage(named: "lightStatusIconDisabled")!
                statusBarIcon.isTemplate = false
                if let statusMenuItem = statusMenu.item(withTag: 0) {
                    statusMenuItem.title = "Status: Disabled"
                    
                }
                break
            default:
                // this cannot happen..
                break
        }
        statusItem.image = statusBarIcon
    }
    
    func saveState(_ state: UInt32) {
        currentMode = state
        _ = secureStore.set(String(state), forKey: "ShellGuardState")
    }
    
    func restoreSavedState() {
        if let stateStr = secureStore.get("ShellGuardState") {
            
            currentMode = UInt32(stateStr)!
        } else {
            // always fall back to enforcing mode.
            print("[ERROR] Falling down to ENFORCING")
            currentMode = State.enforcing.rawValue
        }
        if let modeMenuItem = self.modeMenu.item(withTag: Int(currentMode)) {
            modeMenuItem.state = NSOnState
        }
    }
        
    func notify(_ message: String) {
        let notification = NSUserNotification()
        notification.title = "ShellGuard"
        notification.informativeText = message
        notification.soundName = nil
        NSUserNotificationCenter.default().deliver(notification)
    }
    /*
    * Connect to the kext, using a GCD queue (thread).
    * If we cannot connect to the Kext, we will hang in this while loop...
    */
    func connectKext() {
        // Dispath to the newly created quese. GCD take the responsibility for most things.
        kextCommunicationsQueue.async {
            self.connectedToKext = self.kextCommunicate.connectToKext()
            while (!self.connectedToKext) {
                print("[ERROR] Can't connect to kernel control socket! Trying again in 30 seconds")
                sleep(30)
                self.connectedToKext = self.kextCommunicate.connectToKext()
            }
            DispatchQueue.main.async {
                self.setStatusIcon((self.DARK, self.ENABLED))
            }
        }
    }
}

/* We can use some more Stringness. */
extension String {
    func replace(_ string:String, replacement:String) -> String {
        return self.replacingOccurrences(of: string, with: replacement, options: NSString.CompareOptions.literalSearch, range: nil)
    }
    
    /* If used on a path containing spaces, this function could have negative effects. Use trim() */
    func removeWhitespace() -> String {
        return self.replace(" ", replacement: "")
    }
    
    /* Still need space for '\0' in C char buffer, so not <=  */
    func isSmallerThan(_ i: Int) -> Bool {
        return self.characters.count < i
    }
    
    func contains(_ find: String) -> Bool {
        return self.range(of: find) != nil
    }
    
    /* Removed leading and trailing white spaces. */
    func trim() -> String {
        return self.trimmingCharacters(in: CharacterSet.whitespaces)
    }
}



