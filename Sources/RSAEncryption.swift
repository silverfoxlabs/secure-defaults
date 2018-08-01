//
//  RSAEncryption.swift
//  secure-defaults
//
//  Created by David Cilia on 9/20/17.
//

import Foundation
import Security


/// Encrypt using RSA cryptography
public struct RSAEncryption<T : PreferenceDomainType> : EncryptionProvider {
    
    public typealias Domain = T
    public typealias Base64EncodedStringType = String
    public typealias EncryptedType = Base64EncodedStringType
    
    let algorithm : SecKeyAlgorithm = .rsaEncryptionOAEPSHA512AESGCM
    
    public init() {
        
    }
    
    public func nuke() throws -> Void {
        
        //Retrieve the key from the keychain.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnAttributes as String : true,
            kSecMatchLimit as String : kSecMatchLimitAll
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status != errSecSuccess {
            
            if status == errSecItemNotFound {
                throw EncryptionProviderError.failure(reason: "Item not found.")
            }
            
            throw EncryptionProviderError.couldNotRetrieveKey
        }
        
        let tempResults = item as! CFArray
        let results = tempResults as! Array<Dictionary<String,Any>>
        for attributes in results {
            
            var copyAttr = attributes
            copyAttr[kSecClass as String] = kSecClassKey
            
            let res = SecItemDelete(copyAttr as CFDictionary)
            if res != errSecSuccess {
                throw EncryptionProviderError.couldNotDeleteKeys
            }
        }
    }
    
    public func encrypt(input: T) throws -> Base64EncodedStringType {
        
        //Retrieve the key from the keychain.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        
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
                 kSecPrivateKeyAttrs as String: attributesPrivate,
                 ]
            
            print(attributes.debugDescription)
            
            var unsafe : Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &unsafe) else {
                throw EncryptionProviderError.failedEncryption(reason: unsafe?.takeRetainedValue().localizedDescription ?? "No Error Provided")
            }
            keyPublic = SecKeyCopyPublicKey(privateKey)
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
        
        //TODO: REMOVE DEBUGGING
        print(#function)
        print(T.tag)
        
        
        //Retrieve the key from the keychain.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        
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
            
            if status == errSecItemNotFound {
                throw EncryptionProviderError.failedDecryption(reason: "The item cannot be found.")
            }
            
            throw EncryptionProviderError.failedDecryption(reason: "OSS : \(status)")
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
