import Foundation


/*
 * Just logs to a default location. 
 */
class Logger {
    
    static let sharedInstance = Logger()
    let logFilePath:NSString = "~/Documents/ShellGuard_log.txt"
    
    /* Check if path exists. */
    func logExists() -> Bool {
        return FileManager().fileExists(atPath: logFilePath.expandingTildeInPath)
    }
    
    /* Appends content to (log) file. Returns an error message. */
    func log(_ content: String) -> String? {
        if !logExists() {
            FileManager().createFile(atPath: logFilePath.expandingTildeInPath as String,
                                                contents: nil, attributes: nil)
        }
        if let fileHandle = FileHandle(forWritingAtPath: logFilePath.expandingTildeInPath) {
            fileHandle.seekToEndOfFile()
            if let data = String(getCurrentTime() + content + "\n").data(using: String.Encoding.utf8) {
                fileHandle.write(data)
            } else {
                return "Content to log is not UTF-8 encoded."
            }
            fileHandle.closeFile()
        }
        else {
            return "Can't open the log file."
        }
        return nil
    }
    
    /* Format: DD/MM/YY hh:mm:ss */
    func getCurrentTime() -> String {
        let date = Date()
        let dateFormatter = DateFormatter()
        dateFormatter.timeStyle = DateFormatter.Style.mediumStyle
        dateFormatter.dateStyle = DateFormatter.Style.shortStyle
        dateFormatter.timeZone = TimeZone()
        return String(dateFormatter.string(from: date)) + ": "
    }
}
