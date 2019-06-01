//
//  ECDSAEncryption.swift
//  secure-defaults
//
//  Created by David Cilia on 9/20/17.
//

import Foundation
import Security


/// Encrypt using the Elliptical Curve cryptography
public struct ECDSAEncryption<T : PreferenceDomainType> : EncryptionProvidable {
    
    public typealias Domain = T
    public typealias EncryptedType = String
    public typealias Algorithm = SecKeyAlgorithm
    
    public var algorithm : Algorithm = .eciesEncryptionCofactorX963SHA256AESGCM
    public var useSecureEnclave = false
    
    public init() {
        
    }
    
    public func encrypt(input: T) throws -> String {
        
        //Retrieve the key from the keychain.
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        var keyPublic : SecKey
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            guard let publicKey = SecKeyCopyPublicKey(key) else {
                throw EncryptionProvidableError.failedEncryption(reason: "Could not copy the public key")
            } //get the public key
            
            keyPublic = publicKey
        }
        else {
            //Create new key
            var attributes: [String: Any] = [
                kSecAttrKeyType as String:            kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String:      256,
                kSecPrivateKeyAttrs as String: attributesPrivate,
            ]
            
            var errorPtr : Unmanaged<CFError>?
            
            if useSecureEnclave == true {
                attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
                //Must use SecKeyGeneratePair function for the Secure Enclave
                var privatekeyPtr : SecKey?
                var publicKeyPtr : SecKey?
                
                let status = SecKeyGeneratePair(attributes as CFDictionary, &publicKeyPtr, &privatekeyPtr)
                if status != errSecSuccess {
                    throw EncryptionProvidableError.failedEncryption(reason: "Could not generate EC keys using the Secure Enclave")
                }
                
                guard let key = publicKeyPtr else {
                    throw EncryptionProvidableError.failedEncryption(reason: "SecKeyGeneratePair did not return a public key for the EC key generation with the Secure Enclave.")
                }
                
                keyPublic = key
            }
            else {
                guard let privateKey : SecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &errorPtr) else {
                    throw EncryptionProvidableError.failedEncryption(reason: errorPtr?.takeRetainedValue().localizedDescription ?? "No Error")
                }
                
                guard let key = SecKeyCopyPublicKey(privateKey) else {
                    throw EncryptionProvidableError.failedEncryption(reason: "Could not get public key.")
                }
                
                keyPublic = key
            }
        }
        
        
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .xml
        let data = try! encoder.encode(input)
        var errorPtr : Unmanaged<CFError>?
        let signedPayload = SecKeyCreateEncryptedData(keyPublic, algorithm, data as CFData, &errorPtr)
        
        if let errorStr = errorPtr?.takeRetainedValue().localizedDescription {
            
            throw EncryptionProvidableError.failedEncryption(reason: errorStr)
        }
        
        let payload = signedPayload as Data?
        let toSave = payload?.base64EncodedString() ?? ""
        return toSave
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
    
    public func nuke() throws -> Void {
        
        //Retrieve the key from the keychain.
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecReturnAttributes as String : true,
            kSecMatchLimit as String : kSecMatchLimitAll
        ]
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status != errSecSuccess {
            
            if status == errSecItemNotFound {
                throw EncryptionProvidableError.failure(reason: "Item not found.")
            }
            
            throw EncryptionProvidableError.couldNotRetrieveKey
        }
        
        let tempResults = item as! CFArray
        let results = tempResults as! Array<Dictionary<String,Any>>
        
        
        for attributes in results {
            
            var copyAttr = attributes
            copyAttr[kSecClass as String] = kSecClassKey
            
            if useSecureEnclave == true {
                query[kSecReturnAttributes as String] = nil
                query[kSecMatchLimit as String] = nil
                
                let res = SecItemDelete(query as CFDictionary)
                if res != errSecSuccess {
                    throw EncryptionProvidableError.couldNotDeleteKeys
                }
            }
            else {
             
                let res = SecItemDelete(copyAttr as CFDictionary)
                if res != errSecSuccess {
                    throw EncryptionProvidableError.couldNotDeleteKeys
                }
            }
        }
    }
    
    public func decrypt(input: String) throws -> T {
        //Retrieve the key from the keychain.
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
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
            throw EncryptionProvidableError.failedDecryption(reason: "")
        }
    }
}
