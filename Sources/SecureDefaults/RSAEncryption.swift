//
//  RSAEncryption.swift
//  secure-defaults
//
//  Created by David Cilia on 9/20/17.
//

import Foundation
import Security


/// Encrypt using RSA cryptography
public struct RSAEncryption<T : PreferenceDomainType> : EncryptionProvider where T: Codable {
    
    var algorithm : SecKeyAlgorithm
    
    private let fetchQuery: [String: Any] = {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
    }()
    
    private let nukeQuery: [String: Any] = {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnAttributes as String : true,
            kSecMatchLimit as String : kSecMatchLimitAll
        ]
    }()
    
    private let encryptQuery: [String: Any] = {
       return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
    }()
    
    
    public var attributesPublic: [String : Any] {
        return [:]
    }
    
    public var attributesPrivate: [String : Any] {
        return [
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrIsPermanent as String:    true
        ]
    }
    
    public init(algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA512AESGCM) {
        
        self.algorithm = algorithm
    }
    
    public func nuke() throws -> Void {
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(nukeQuery as CFDictionary, &item)
        
        switch status {
        case errSecItemNotFound:
            throw EncryptionProviderError.failure(reason: "Item not found.")
        case errSecSuccess:
            break
        default:
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
    
    public func encrypt(data input: T) throws -> EncryptedType {
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(encryptQuery as CFDictionary, &item)
        var keyPublic : SecKey?
        
        switch status {
        case errSecSuccess:
            let key = item as! SecKey //private key
            keyPublic = SecKeyCopyPublicKey(key) //get the public key
            break
        default:
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
            break
        }
        
        guard let k = keyPublic else {
            throw EncryptionProviderError.failedEncryption(reason: "Public key was nil.")
        }
        
        
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .xml
        
        let data: Data
        
        do {
            data = try encoder.encode(input)
        }
        catch {
            throw EncryptionProviderError.failedEncryption(reason: error.localizedDescription)
        }
        
        var unsafe : Unmanaged<CFError>?
        let signedPayload = SecKeyCreateEncryptedData(k, algorithm, data as CFData, &unsafe)
        
        if let errorStr = unsafe?.takeRetainedValue().localizedDescription {
            throw EncryptionProviderError.failedEncryption(reason: errorStr)
        }
                
        guard let p = signedPayload as Data? else {
            throw EncryptionProviderError.failedEncryption(reason: "encryption data was nil.")
        }
        
        let toSave = p.base64EncodedString()
        return toSave
    }
    
  
    
    public func decrypt(data input: String) throws -> T {
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(fetchQuery as CFDictionary, &item)
        
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
}
