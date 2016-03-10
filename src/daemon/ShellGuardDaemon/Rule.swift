import Foundation


class Rule {
    var processName: String
    var kAuthOperation: String
    var path: String
    var allowRoot: Bool
    var pathWildcard: UInt32
    var kAuthAction: UInt32
    var kAuthOp: UInt32
    
    init(proc: String, operation: String, op: UInt32, path: String, root: Bool, path_wildcard: UInt32, action: UInt32) {
        self.processName = proc
        self.kAuthOperation = operation
        self.kAuthOp = op
        self.path = path
        self.allowRoot = root
        self.pathWildcard = path_wildcard
        self.kAuthAction = action
    }
    
    func toString() -> String {
        var printPath = self.path
        var printAction:String
        if pathWildcard == 1 {
            printPath += "*"
        }
        if kAuthAction == 1 {
            printAction = "allowed"
        } else {
            printAction = "denied"
        }
        return "\"\(kAuthOperation)\"\t (\(kAuthOp)) \(printAction) for \"\(processName)\"\t on \t\"\(printPath)\". Root allowed: \"\(allowRoot)\""
    }
}
