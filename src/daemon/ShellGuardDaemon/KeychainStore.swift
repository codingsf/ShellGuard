import Foundation
import Security

/*
 * KeychainStore is used to store and retrieve data from Keychain. Keychain should
 * be a safe place for applications to store their cirital info. Large portions of the
 * code for this implemantation is taken from keychain-swift by Marketplacer.
 * https://github.com/marketplacer/keychain-swift
 */
class KeychainStore {
    
    var lastResultCode: OSStatus = noErr
    var accessGroup: String?
    
    
    /* Singleton. This prevents others from using the default '()' initializer for this class. */
    static let sharedInstance = KeychainStore()
    private init() {}
    
    /* Set key:String value:String pair in Keychain. */
    func set(value: String, forKey key: String) -> Bool {
        if let value = value.dataUsingEncoding(NSUTF8StringEncoding) {
            
            delete(key) // Delete any existing key before saving it
            
            var query = [
                KeychainSwiftConstants.klass       : kSecClassGenericPassword,
                KeychainSwiftConstants.attrAccount : key,
                KeychainSwiftConstants.valueData   : value,
                KeychainSwiftConstants.accessible  : String(kSecAttrAccessibleAfterFirstUnlock)
            ]
            query = addAccessGroupWhenPresent(query)
            lastResultCode = SecItemAdd(query as CFDictionaryRef, nil)
            
            return lastResultCode == noErr
        }
        return false
    }
    
    /* Get value for key:String from Keychain. */
    func get(key: String) -> String? {
        if let data = getData(key) {
            if let currentString = NSString(data: data, encoding: NSUTF8StringEncoding) as? String {
                return currentString
            }
            lastResultCode = -67853 // errSecInvalidEncoding
        }
        return nil
    }
    
    /* Get NSData object from Keychain. */
    func getData(key: String) -> NSData? {
        
        var query: [String: NSObject] = [
            KeychainSwiftConstants.klass       : kSecClassGenericPassword,
            KeychainSwiftConstants.attrAccount : key,
            KeychainSwiftConstants.returnData  : kCFBooleanTrue,
            KeychainSwiftConstants.matchLimit  : kSecMatchLimitOne ]
        
        query = addAccessGroupWhenPresent(query)
        
        var result: AnyObject?
        lastResultCode = withUnsafeMutablePointer(&result) {
            SecItemCopyMatching(query, UnsafeMutablePointer($0))
        }
        if lastResultCode == noErr { return result as? NSData }
        
        return nil
    }
    
    /* Delete key:String from Keychain. */
    func delete(key: String) -> Bool {
        
        var query: [String: NSObject] = [
            KeychainSwiftConstants.klass       : kSecClassGenericPassword,
            KeychainSwiftConstants.attrAccount : key ]
        
        query = addAccessGroupWhenPresent(query)
        
        lastResultCode = SecItemDelete(query as CFDictionaryRef)
        
        return lastResultCode == noErr
    }
    
    /* Retrieve AccesGroup for a Keychain item. */
    func addAccessGroupWhenPresent(items: [String: NSObject]) -> [String: NSObject] {
        guard let accessGroup = accessGroup else { return items }
        
        var result: [String: NSObject] = items
        result[KeychainSwiftConstants.accessGroup] = accessGroup
        return result
    }
}

struct KeychainSwiftConstants {
    // Specifies a Keychain access group. Used for sharing Keychain items between apps.
    static var accessGroup: String { return toString(kSecAttrAccessGroup) }
    
    /* A value that indicates when your app needs access to the data in a keychain item. The default value is AccessibleWhenUnlocked. For a list of possible values, see KeychainSwiftAccessOptions. */
    static var accessible: String { return toString(kSecAttrAccessible) }
    
    // Used for specifying a String key when setting/getting a Keychain value.
    static var attrAccount: String { return toString(kSecAttrAccount) }
    
    // An item class key used to construct a Keychain search dictionary.
    static var klass: String { return toString(kSecClass) }
    
    // Specifies the number of values returned from the keychain. The library only supports single values.
    static var matchLimit: String { return toString(kSecMatchLimit) }
    
    // A return data type used to get the data from the Keychain.
    static var returnData: String { return toString(kSecReturnData) }
    
    // Used for specifying a value when setting a Keychain value.
    static var valueData: String { return toString(kSecValueData) }
    
    static func toString(value: CFStringRef) -> String {
        return value as String
    }
}

