import Foundation


/*
 * Just logs to a default location. 
 */
class Logger {
    
    static let sharedInstance = Logger()
    let logFilePath:NSString = "~/Documents/ShellGuard_log.txt"
    
    /* Check if path exists. */
    func logExists() -> Bool {
        return NSFileManager().fileExistsAtPath(logFilePath.stringByExpandingTildeInPath)
    }
    
    /* Appends content to (log) file. Returns an error message. */
    func log(content: String) -> String? {
        if !logExists() {
            NSFileManager().createFileAtPath(logFilePath.stringByExpandingTildeInPath as String,
                                                contents: nil, attributes: nil)
        }
        if let fileHandle = NSFileHandle(forWritingAtPath: logFilePath.stringByExpandingTildeInPath) {
            fileHandle.seekToEndOfFile()
            if let data = String(getCurrentTime() + content + "\n").dataUsingEncoding(NSUTF8StringEncoding) {
                fileHandle.writeData(data)
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
        let date = NSDate()
        let dateFormatter = NSDateFormatter()
        dateFormatter.timeStyle = NSDateFormatterStyle.MediumStyle
        dateFormatter.dateStyle = NSDateFormatterStyle.ShortStyle
        dateFormatter.timeZone = NSTimeZone()
        return String(dateFormatter.stringFromDate(date)) + ": "
    }
}