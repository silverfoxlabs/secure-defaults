//
//  ECDSAEncryption.swift
//  secure-defaults
//
//  Created by David Cilia on 9/20/17.
//

import Foundation
import Security



/// Encrypt using the Elliptical Curve cryptography
public struct ECDSAEncryption<T : PreferenceDomainType> : EncryptionProvider where T: Codable {
        
    let algorithm : SecKeyAlgorithm
    public var useSecureEnclave: Bool
    
    private let encryptQuery: [String: Any] = {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
    }()
    
    private let fetchQuery: [String: Any] = {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
    }()
    
    private let nukeQuery: [String: Any] = {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecReturnAttributes as String : true,
            kSecMatchLimit as String : kSecMatchLimitAll
        ]
    }()
    
    
    public init(algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM, useSecureEnclave: Bool = false) {
        self.algorithm = algorithm
        self.useSecureEnclave = useSecureEnclave
    }
    
    public func encrypt(data input: T) throws -> String {
        
        var query = encryptQuery
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(encryptQuery as CFDictionary, &item)
        var keyPublic : SecKey
        
        switch status {
        case errSecSuccess:
            let key = item as! SecKey //private key
            guard let publicKey = SecKeyCopyPublicKey(key) else {
                throw EncryptionProviderError.failedEncryption(reason: Reasons.couldNotCopyPublicKey)
            } //get the public key
            
            keyPublic = publicKey
            break
        default:
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
                    throw EncryptionProviderError.failedEncryption(reason: Reasons.couldNotCopySecureEnclave)
                }
                
                guard let key = publicKeyPtr else {
                    throw EncryptionProviderError.failedEncryption(reason: Reasons.failedEncryption)
                }
                
                keyPublic = key
            }
            else {
                guard let privateKey : SecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &errorPtr) else {
                    throw EncryptionProviderError.failedEncryption(reason: errorPtr?.takeRetainedValue().localizedDescription ?? "No Error")
                }
                
                guard let key = SecKeyCopyPublicKey(privateKey) else {
                    throw EncryptionProviderError.failedEncryption(reason: Reasons.failGetPublicKey)
                }
                
                keyPublic = key
            }
            break
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

        var errorPtr : Unmanaged<CFError>?
        let signedPayload = SecKeyCreateEncryptedData(keyPublic, algorithm, data as CFData, &errorPtr)
        
        if let errorStr = errorPtr?.takeRetainedValue().localizedDescription {
            
            throw EncryptionProviderError.failedEncryption(reason: errorStr)
        }
        
        guard let payload = signedPayload as Data? else {
            throw EncryptionProviderError.failedEncryption(reason: "payload data is nil.")
        }
        let toSave = payload.base64EncodedString()
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
        
        var query = nukeQuery
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        switch status {
        case errSecSuccess:
            break
        case errSecItemNotFound:
            throw EncryptionProviderError.failure(reason: "Item not found.")
        default:
            throw EncryptionProviderError.couldNotRetrieveKey
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
                    throw EncryptionProviderError.couldNotDeleteKeys
                }
            }
            else {
             
                let res = SecItemDelete(copyAttr as CFDictionary)
                if res != errSecSuccess {
                    throw EncryptionProviderError.couldNotDeleteKeys
                }
            }
        }
    }
    
    public func decrypt(data input: String) throws -> T {

        var query = fetchQuery
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
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
            throw EncryptionProviderError.failedDecryption(reason: Reasons.unknownError)
        }
    }
}
