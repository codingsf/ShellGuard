
import Foundation


/*
 * ConfigLoader is responsible for reading/loading the configuration for ShellGuard.
 * ConfigLoader is a Singleton class.
 *
 */
class ConfigLoader {
    var whitelist: [Item]
    var shellList: [Item]
    var structLengths: [Int]
    let PROCNAME        = 0
    let SHELL           = 1
    
    let MAX_PROC_LEN    = 1023
    let MAX_PATH_LEN    = 1023

    /* Singleton. This prevents others from using the default '()' initializer for this class. */
    static let sharedInstance = ConfigLoader()
    
    private init() {
        self.structLengths = [MAX_PROC_LEN, MAX_PATH_LEN]
        self.whitelist = [Item]()
        self.shellList = [Item]()
    }
    
    func getWhitelist() -> [Item] {
        return self.whitelist
    }
    
    func emptyWhitelist() {
        self.whitelist.removeAll()
    }
    
    func getShellList() -> [Item] {
        return self.shellList
    }
    
    /* 
     * Responsible for parsing the JSON config file and creating Whitelist/Shell objects from them.
     */
    func loadConfigFile(fileLocation: String) {
        let location = NSString(string:fileLocation).stringByExpandingTildeInPath
        if let fileContent = try? NSString(contentsOfFile: location, encoding: NSUTF8StringEncoding) as String {
            if let dataFromString = fileContent.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) {
                let json = JSON(data: dataFromString)
                if json != JSON.null {
                    for (_, value) in json {
                        if let procname = value["process_name"].string {
                            if let shells = value["shells"].array {
                                for shell in shells {
                                    if let s = shell.string {
                                        validateItem([procname, s])
                                    }
                                }
                            }
                        }
                    }
                    for (_, value) in json {
                        if let blackListedShells = value["black_listed_shells"].array {
                            for s in blackListedShells {
                                if let shell = s.string {
                                    print(shell)
                                    validateBlacklistedShell(shell)
                                }
                            }
                        }
                    }
                } else {
                    print("[ERROR] Config file is not valid JSON.")
                }
            }
        } else {
            print("[ERROR] Invalid filename/path.")
        }
    }
    
    
    /*
    * Check wether the config is not malformed and convert to Item object. Below are some helper functions.
    */
    func validateItem(stringConf: [String]) {
        /* check length of input */
        for (index, r) in stringConf.enumerate() {
            guard r.trim().isSmallerThan(structLengths[index]) else {
                malformedItem(stringConf)
                return
            }
        }
        whitelist.append(Item( proc: stringConf[PROCNAME].trim(),
                                    shell: stringConf[SHELL].trim()))
    }
    
    func validateBlacklistedShell(shell: String) {
        guard shell.trim().isSmallerThan(MAX_PATH_LEN) else {
            malformedItem([shell])
            return
        }
        shellList.append(Item(proc: "N/A", shell: shell))
    }
    
    func malformedItem(s: [String]) {
        var res = ""
        for i in s {
            res += ", " + i
        }
        print("[[ERROR] Malformatted config: \(res)")
    }
    
}