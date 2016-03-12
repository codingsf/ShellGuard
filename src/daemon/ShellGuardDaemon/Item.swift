
import Foundation


class Item {
    var processName: String
    var shell: String
    
    init(proc: String, shell: String) {
        self.processName = proc
        self.shell = shell
    }
    
    func toString() -> String {
        if self.processName == "" {
            return "\(shell) is blacklisted."
        } else {
            return "\(shell)\t allowed for \(processName)."
        }
    }
}