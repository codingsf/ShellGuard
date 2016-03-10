import Foundation


/*
 * LoadRules is responsible for reading/loading and maintaining the rules and policies.
 * LoadRules is a Singleton class.
 *
 */
class RulesLoader {
    var rules: [Rule]
    var ruleStructLengths: [Int]
    let PROC            = 0
    let OPERATION       = 1
    let PATH            = 2
    
    let MAX_PROC_LEN    = 256
    let MAX_KAUTH_OP    = 256
    let MAX_PATH_LEN    = 1024

    /* Singleton. This prevents others from using the default '()' initializer for this class. */
    static let sharedInstance = RulesLoader()
    private init() {
        self.ruleStructLengths = [ MAX_PROC_LEN, MAX_KAUTH_OP, MAX_PATH_LEN ]
        self.rules = [Rule]()
    }
    
    func getLoadedRules() -> [Rule] {
        return self.rules
    }
    
    func emptyLoadedRules() {
        self.rules.removeAll()
    }
    
    /* 
     * Responsible for parsing the JSON policy file and creating Rule objects from them.
     */
    func readJSONPocilies(fileLocation: String) {
        let location = NSString(string:fileLocation).stringByExpandingTildeInPath
        if let fileContent = try? NSString(contentsOfFile: location, encoding: NSUTF8StringEncoding) as String {
            if let dataFromString = fileContent.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) {
                let json = JSON(data: dataFromString)
                if json != JSON.null {
                    for (_, value) in json {
                        if let procname = value["process_name"].string {
                            if let rules = value["rules"].array {
                                for rule in rules {
                                    if let path = rule["path"].string,
                                       let rt   = rule["root"].bool,
                                       let ops  = rule["operations"].array,
                                       let act  = rule["allowed"].bool {
                                        for j in ops {
                                            if let op = j.string {
                                             validateRule([procname, op, path], root: rt, action: act)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    print("[ERROR] Policy file is not valid JSON.")
                }
            }
        } else {
            print("[ERROR] Invalid filename/path.")
        }
    }
    
    /*
    * Check wether the rule is not malformed and convert to Rule object. Below are some helper functions.
    */
    func validateRule(stringConf: [String], root: Bool, action: Bool) {
        /* check length of input */
        for (index, r) in stringConf.enumerate() {
            guard r.trim().isSmallerThan(ruleStructLengths[index]) else {
                malformedRule(stringConf)
                return
            }
        }
        
        guard let operation = convertKAuthOperation(stringConf[OPERATION]) else {
            malformedRule(stringConf)
            return
        }
        
        let (path, wildcard) = checkWildCard(stringConf[PATH])
        
        rules.append(Rule(
            proc: stringConf[PROC].trim(),
            operation: stringConf[OPERATION].trim(),
            op: UInt32(operation),
            path: path.trim(),
            root: root,
            path_wildcard: UInt32(wildcard),
            action: convertKAuthAction(action)
            ))
    }

    
    func checkWildCard(s: String) -> (String, Int) {
        if s.hasSuffix("*") {
            return (String(s.characters.dropLast()), 1)
        } else {
            return (s, 0)
        }
    }
    
    
    func convertKAuthOperation(s: String) -> Int? {
        let op = s.trim()
        switch op {
        case "READ":
            return 2
        case "WRITE":
            return 4
        case "EXECUTE":
            return 8
        default:
            return nil
        }
    }
    
    func convertKAuthAction(s: Bool) -> UInt32 {
        return s ? 1 : 0
    }
    
    func malformedRule(s: [String]) {
        var res = ""
        for i in s {
            res += ", " + i
        }
        print("[[ERROR] Malformatted rule: \(res)")
    }
    
}