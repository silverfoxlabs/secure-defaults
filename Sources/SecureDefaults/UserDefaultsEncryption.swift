//
//  UserDefaultsEncryption.swift
//  SecureDefaults
//
//  Created by David Cilia on 3/15/20.
//

import Foundation



/// Encrypt & Decrypt User Defaults Values
/**
Summary of algortithm using symmetric crypto to encrypt/decrypt
with assymetric keypair:
1. Create the private key if it doesn't exist; otherwise fetch it.
2. Use  public key to encrypt the data - calling
   SecKeyCreateEncryptedData
3. Use the private key to decrypt the data - calling:
   SecKeyCreateDecryptedData
*/
public struct UserDefaultsEncryption<T: PreferenceDomainType>: EncryptionProvider where T: Codable {

    var keyType: EncryptionType

    public init(_ config: EncryptionType) {
        keyType = config
    }

    public func nuke() throws -> Void {

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: T.tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: keyType.values().0,
            kSecReturnAttributes as String : true,
            kSecMatchLimit as String : kSecMatchLimitAll
        ]


        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

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


    /// Encrypting data for User Defaults
    /// - Parameter input: the data to encrypt.
    public func encrypt(data input: T) throws -> EncryptedType {

        //Note: Use public key to encrypt data!

        let key = try KeyMaker.fetch(keyWith: T.tag,
                                              type: keyType.values().0,
                                              name: T.name,
                                              size: keyType.values().2)


        print(SecKeyCopyAttributes(key))


        let encoder = PropertyListEncoder()
        encoder.outputFormat = .xml

        let data: Data

        do {
            data = try encoder.encode(input)
        }
        catch {
            throw EncryptionProviderError.failedEncryption(reason: error.localizedDescription)
        }

        let pKey = try KeyMaker.getPublicKey(key: key)

        var unsafe : Unmanaged<CFError>?
        let signedPayload = SecKeyCreateEncryptedData(pKey,
                                                      keyType.values().1,
                                                      data as CFData,
                                                      &unsafe)


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

        //Note: Decrypt data with Private Key!

        let key = try KeyMaker.fetch(keyWith: T.tag,
                                              type: keyType.values().0,
                                              name: T.name,
                                              size: keyType.values().2)

        let data = input.data(using: .utf8)! as CFData
        var error : Unmanaged<CFError>?
        let algo = keyType.values().1
        guard let result = SecKeyCreateDecryptedData(key, algo, data, &error) else {
            print("DecryptedData == nil")
            throw EncryptionProviderError.failure(reason: error?.takeRetainedValue().localizedDescription ?? "No error provided by the Security Framework.")
        }

        let decoder = PropertyListDecoder()
        let retVal = try decoder.decode(T.self, from: result as Data)
        return retVal
    }
}
