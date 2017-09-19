
import Foundation
import Security

public enum EncryptionProviderError : Error {
    
    case failedEncryption(reason: String)
    case inputError
    case failedDecryption(reason : String)
    case couldNotRetrieveKey
}

public protocol EncryptionProvider {
    
    associatedtype Domain
    associatedtype EncryptedType
    
    var attributesPublic : [ String : Any] { get }
    var attributesPrivate : [String : Any] { get }
    func encrypt(input: Domain) throws -> EncryptedType
    func decrypt(input: EncryptedType) throws -> Domain
    func nuke() throws -> Void

}

public protocol PreferenceDomainType : Codable {
    /// The name of your PreferenceDomainType
    /// - Note: Generally you will want to use a
    /// a reverse domain style string.  This value
    /// will be used to register with the UserDefaults.
    static var name : String { get }
    /// The key to use for the defaults dictionary
    static var key : String { get }
    /// Tag for Keychain Storage & Retrieval
    static var tag : String { get }
    /// Registers your PreferenceDomain with the User Defaults
    /// - Note: Uses the 'key' var as your key, with a String value
    /// ie: ["myPreferenceKey" : "some hashed value"]
    /// - Returns: Void
    func register() -> Void
    /// Saving the preference domain type to the suite
    ///
    /// - Parameter input: an encrypted string of the PreferenceDomainType
    /// - Returns: Void
    func save(encryptedPayload : String) -> Void
}

public extension PreferenceDomainType {
    
    func register() -> Void {
        UserDefaults.standard.addSuite(named: Self.name)
        let suite = UserDefaults(suiteName: Self.name)
        suite?.register(defaults: [Self.key : ""])
    }
    
    func save(encryptedPayload: String) -> Void {
        let suite = UserDefaults(suiteName: Self.name)
        suite?.set(encryptedPayload, forKey: Self.key)
        suite?.synchronize()
        UserDefaults.standard.synchronize()
    }
}


public struct RSAEncryption<T : PreferenceDomainType> : EncryptionProvider {
    
    public typealias Domain = T
    public typealias Base64EncodedStringType = String
    public typealias EncryptedType = Base64EncodedStringType
    
    let algorithm : SecKeyAlgorithm = .rsaEncryptionOAEPSHA512AESGCM
    
    public init() {
        
    }
    
    public func nuke() throws -> Void {
        
        //Retrieve the key from the keychain.
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: T.tag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecReturnRef as String: true,
                                    kSecMatchLimit as String : kSecMatchLimitAll
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        print(item.debugDescription)
        
        if status == errSecSuccess {
            let _status = SecItemDelete(query as CFDictionary)
            if _status != errSecSuccess {
                throw EncryptionProviderError.couldNotRetrieveKey
            }
        }
    }
    
    public func encrypt(input: T) throws -> Base64EncodedStringType {
    
        //Retrieve the key from the keychain.
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: T.tag,
                                       kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                       kSecReturnRef as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        var keyPublic : SecKey?
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            keyPublic = SecKeyCopyPublicKey(key) //get the public key
        }
        else {
            //Create new key
            let attributes: [String: Any] =
                [kSecAttrKeyType as String:            kSecAttrKeyTypeRSA,
                 kSecAttrKeySizeInBits as String:      2048,
                 kSecPublicKeyAttrs as String : attributesPublic,
                 kSecPrivateKeyAttrs as String: attributesPrivate,
                 kSecAttrLabel as String : T.name,
                 kSecAttrComment as String : "created using the secure_defaults.framework"
            ]
            
            print(attributes.debugDescription)
            
            var unsafe : Unmanaged<CFError>?
            let privateKey : SecKey? = SecKeyCreateRandomKey(attributes as CFDictionary, &unsafe)
            keyPublic = SecKeyCopyPublicKey(privateKey!)
        }
        
        
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .xml
        let data = try! encoder.encode(input)
        var unsafe : Unmanaged<CFError>?
        let signedPayload = SecKeyCreateEncryptedData(keyPublic!, algorithm, data as CFData, &unsafe)
        
        if let errorStr = unsafe?.takeRetainedValue().localizedDescription {
        
            throw EncryptionProviderError.failedEncryption(reason: errorStr)
        }
        
        let payload = signedPayload as Data?
        let toSave = payload!.base64EncodedString()
        return toSave
    }
    
    public func decrypt(input: Base64EncodedStringType) throws -> T {
        
        //Retrieve the key from the keychain.
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: T.tag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecReturnRef as String: true]
        
        print(query.debugDescription)
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            guard let data = Data(base64Encoded: input) else {
                throw EncryptionProviderError.inputError
            }
            
            var error : Unmanaged<CFError>?
            guard let result = SecKeyCreateDecryptedData(key, algorithm, data as CFData, &error) else {
                throw EncryptionProviderError.failedDecryption(reason: "\(error?.takeRetainedValue().localizedDescription ?? "No Error")")
            }
            
            let decoder = PropertyListDecoder()
            
            do {
                let retVal = try decoder.decode(T.self, from: result as Data)
                return retVal
            }
            catch {
                throw EncryptionProviderError.failedDecryption(reason: error.localizedDescription)
            }
        }
        else {
            throw EncryptionProviderError.failedDecryption(reason: "")
        }
    }
    
    public var attributesPublic: [String : Any] {
        return [
            kSecAttrIsPermanent as String:    true,
            kSecAttrApplicationTag as String: T.tag,
            kSecAttrCanEncrypt as String : true
        ]
    }
    
    public var attributesPrivate: [String : Any] {
        return [
            
            kSecAttrIsPermanent as String:    true,
            kSecAttrApplicationTag as String: T.tag,
            kSecAttrCanDecrypt as String : true,
        ]
    }
}

public struct ECDSAEncryption<T : PreferenceDomainType> : EncryptionProvider {
    
    public func nuke() throws -> Void {
        
        //Retrieve the key from the keychain.
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: T.tag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeECDSA,
                                    kSecReturnRef as String: true
        ]
        
        print(query.debugDescription)
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            let _status = SecItemDelete(query as CFDictionary)
            if _status != errSecSuccess {
                throw EncryptionProviderError.couldNotRetrieveKey
            }
        }
    }
    
    public func decrypt(input: String) throws -> T {
        //Retrieve the key from the keychain.
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: T.tag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeECDSA,
                                    kSecReturnRef as String: true]
        
        print(query.debugDescription)
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            guard let data = Data(base64Encoded: input) else {
                throw EncryptionProviderError.inputError
            }
            
            var error : Unmanaged<CFError>?
            guard let result = SecKeyCreateDecryptedData(key, algorithm, data as CFData, &error) else {
                throw EncryptionProviderError.failedDecryption(reason: "\(error?.takeRetainedValue().localizedDescription ?? "No Error")")
            }
            
            let decoder = PropertyListDecoder()
            
            do {
                let retVal = try decoder.decode(T.self, from: result as Data)
                return retVal
            }
            catch {
                throw EncryptionProviderError.failedDecryption(reason: error.localizedDescription)
            }
        }
        else {
            throw EncryptionProviderError.failedDecryption(reason: "")
        }    }
    
    public typealias Domain = T
    public typealias EncryptedType = String
    
    let algorithm : SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
    
    public init() {
        
    }
    
    public func encrypt(input: T) throws -> String {
        
        //Retrieve the key from the keychain.
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: T.tag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeECDSA,
                                    kSecReturnRef as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        var keyPublic : SecKey?
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            keyPublic = SecKeyCopyPublicKey(key) //get the public key
        }
        else {
            //Create new key
            let attributes: [String: Any] =
                [kSecAttrKeyType as String:            kSecAttrKeyTypeECSECPrimeRandom,
                 kSecAttrKeySizeInBits as String:      256,
                 kSecPublicKeyAttrs as String : attributesPublic,
                 kSecPrivateKeyAttrs as String: attributesPrivate,
                 kSecAttrLabel as String : T.name,
                 kSecAttrComment as String : "created using the secure_defaults.framework"
            ]
            
            print(attributes.debugDescription)
            
            var unsafe : Unmanaged<CFError>?
            guard let privateKey : SecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &unsafe) else {
                throw EncryptionProviderError.failedEncryption(reason: unsafe?.takeRetainedValue().localizedDescription ?? "No Error")
            }
            
            guard let key = SecKeyCopyPublicKey(privateKey) else {
                throw EncryptionProviderError.failedEncryption(reason: "Could not get public key.")
            }
            
            keyPublic = key
        }
        
        
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .xml
        let data = try! encoder.encode(input)
        var unsafe : Unmanaged<CFError>?
        let signedPayload = SecKeyCreateEncryptedData(keyPublic!, algorithm, data as CFData, &unsafe)
        
        if let errorStr = unsafe?.takeRetainedValue().localizedDescription {
            
            throw EncryptionProviderError.failedEncryption(reason: errorStr)
        }
        
        let payload = signedPayload as Data?
        let toSave = payload?.base64EncodedString() ?? ""
        return toSave
    }
    
    
    public var attributesPublic: [String : Any] {
        return [
            kSecAttrIsPermanent as String:    true,
            kSecAttrApplicationTag as String: T.tag,
            kSecAttrCanEncrypt as String : true
        ]
        
    }
    
    public var attributesPrivate: [String : Any] {
        
        return [
            
            kSecAttrIsPermanent as String:    true,
            kSecAttrApplicationTag as String: T.tag,
            kSecAttrCanDecrypt as String : true
        ]
    }
}
