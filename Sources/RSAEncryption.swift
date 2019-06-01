//
//  RSAEncryption.swift
//  secure-defaults
//
//  Created by David Cilia on 9/20/17.
//

import Foundation
import Security


/// Encrypt using RSA cryptography
public struct RSAEncryption<T : PreferenceDomainType> : EncryptionProvidable {
    
    public typealias Domain = T
    public typealias Base64EncodedStringType = String
    public typealias EncryptedType = Base64EncodedStringType
    public typealias Algorithm = SecKeyAlgorithm

    public var algorithm : SecKeyAlgorithm = .rsaEncryptionOAEPSHA512AESGCM
    
    public init() {}

    /// Deletes Keys with the tag
    ///
    /// - Throws: A EncryptionProviderError
    public func nuke() throws -> Void {

//        guard let data = T.tag.data(using: .utf8) as CFData? else {
//            throw EncryptionProvidableError.failure(reason: "Provider key tag could not be parsed")
//        }

        //Retrieve the key from the keychain.
//        let query: [String: Any] = [
//            kSecClass as String: kSecClassKey,
//            kSecAttrApplicationTag as String: data,
//            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
//            kSecReturnAttributes as String : true,
//            kSecMatchLimit as String : kSecMatchLimitAll,
//            kSecAttrLabel as String : T.name
//        ]

        let query = attributesDefault()

        var item: CFTypeRef?

        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status != errSecSuccess {
            
            if status == errSecItemNotFound {
                throw EncryptionProvidableError.failedEncryption(reason: "Key was not found.")
            }
            
            throw EncryptionProvidableError.couldNotRetrieveKey
        }
        
            let tempResults = item as! CFArray
            guard let results = tempResults as? Array<Dictionary<String,Any>> else {
                throw EncryptionProvidableError.failure(reason: "Could not load any keys")
        }

        for attributes in results {
            
            var copyAttr = attributes
            copyAttr[kSecClass as String] = kSecClassKey
            
            let res = SecItemDelete(copyAttr as CFDictionary)
            if res != errSecSuccess {
                throw EncryptionProvidableError.couldNotDeleteKeys
            }
        }
    }
    
    public func encrypt(input: T) throws -> Base64EncodedStringType {

//        guard let tagData = T.tag.data(using: .utf8) as CFData? else {
//            throw EncryptionProvidableError.failure(reason: "Provider key tag could not be parsed")
//        }
//
//        //Retrieve the key from the keychain.
//        let query: [String: Any] = [
//            kSecClass as String: kSecClassKey,
//            kSecAttrApplicationTag as String: tagData,
//            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
//            kSecReturnRef as String: true,
//            kSecAttrComment as String : "Created By SecureDefaults\n\(T.name)"
//        ]

        let query = attributesDefault()


        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        var keyPublic : SecKey?
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            keyPublic = SecKeyCopyPublicKey(key) //get the public key
        }
        else if status == errSecItemNotFound {
            //Create new key
            let attributes: [String: Any] =
                [kSecAttrKeyType as String:            kSecAttrKeyTypeRSA,
                 kSecAttrKeySizeInBits as String:      2048,
                 kSecPrivateKeyAttrs as String: attributesPrivate,
                 kSecAttrComment as String : "Created By SecureDefaults\n\(T.name)"
                 ]
            
            print(attributes.debugDescription)
            
            var unsafe : Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &unsafe) else {
                throw EncryptionProvidableError.failedEncryption(reason: unsafe?.takeRetainedValue().localizedDescription ?? "No Error Provided")
            }
            keyPublic = SecKeyCopyPublicKey(privateKey)
        }
        else {
            throw EncryptionProvidableError.failedEncryption(reason: "OSStatus Error : \(status)")
        }
        
        
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .xml
        let data = try! encoder.encode(input)
        var unsafe : Unmanaged<CFError>?
        let signedPayload = SecKeyCreateEncryptedData(keyPublic!, algorithm, data as CFData, &unsafe)
        
        if let errorStr = unsafe?.takeRetainedValue().localizedDescription {
            throw EncryptionProvidableError.failedEncryption(reason: errorStr)
        }
        
        let payload = signedPayload as Data?
        let toSave = payload!.base64EncodedString()
        return toSave
    }
    
    public func decrypt(input: Base64EncodedStringType) throws -> T {

        //Retrieve the key from the keychain.
//        let query: [String: Any] = [
//            kSecClass as String: kSecClassKey,
//            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
//            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
//            kSecReturnRef as String: true,
//            kSecAttrComment as String : "Created By SecureDefaults\n\(T.name)"
//        ]

        let query = attributesDefault()


        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            guard let data = Data(base64Encoded: input) else {
                
                throw EncryptionProvidableError.inputError
            }
            
            var error : Unmanaged<CFError>?
            guard let result = SecKeyCreateDecryptedData(key, algorithm, data as CFData, &error) else {
                throw EncryptionProvidableError.failedDecryption(reason: "\(error?.takeRetainedValue().localizedDescription ?? "No Error")")
            }
            
            let decoder = PropertyListDecoder()
            
            do {
                let retVal = try decoder.decode(T.self, from: result as Data)
                return retVal
            }
            catch {
                throw EncryptionProvidableError.failedDecryption(reason: error.localizedDescription)
            }
        }
        else {
            
            if status == errSecItemNotFound {
                throw EncryptionProvidableError.failedDecryption(reason: "The item cannot be found.")
            }
            
            throw EncryptionProvidableError.failedDecryption(reason: "OSS : \(status)")
        }
    }
    
    public var attributesPublic: [String : Any] {
        return [:]
    }
    
    public var attributesPrivate: [String : Any] {
        return [
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrIsPermanent as String:    true
        ]
    }
}

extension RSAEncryption {

    func attributesDefault() -> [String : Any] {
        let tag = T.tag.data(using: .utf8)!
        let attributes : [String : Any] = [

            kSecAttrKeyType as String : kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String : 2048,
            kSecPrivateKeyAttrs as String : [

                kSecAttrIsPermanent as String : true,
                kSecAttrApplicationTag as String : tag,
            ],

            kSecPublicKeyAttrs as String : [
                kSecAttrIsPermanent as String : false,
            ]
        ]

        return attributes
    }
}

