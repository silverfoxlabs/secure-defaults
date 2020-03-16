//
//  UserDefaultsEncryption.swift
//  SecureDefaults
//
//  Created by David Cilia on 3/15/20.
//

import Foundation

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

    public func encrypt(data input: T) throws -> EncryptedType {

        let key = try KeyMaker.fetchPublicKey(tag: T.tag,
                                              type: kSecAttrKeyTypeRSA,
                                              name: T.name)

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
//        let signedPayload = SecKeyCreateSignature(key, .rsaSignatureDigestPSSSHA512, data as CFData, &unsafe)
        let signedPayload = SecKeyCreateEncryptedData(key,
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

        let key = try KeyMaker.fetchPublicKey(tag: T.tag,
                                              type: keyType.values().0,
                                              name: T.name)
        let data = input.data(using: .utf8)!

        var error : Unmanaged<CFError>?
        guard let result = SecKeyCreateDecryptedData(key, keyType.values().1, data as CFData, &error) else { throw EncryptionProviderError.failure(reason: "Could not decrypt data using the cryptographic key.")}

        let decoder = PropertyListDecoder()
        let retVal = try decoder.decode(T.self, from: result as Data)
        return retVal
    }
}
