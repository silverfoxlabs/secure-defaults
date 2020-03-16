//
//  KeyMaker.swift
//  SecureDefaults
//
//  Created by David Cilia on 3/14/20.
//

import Foundation

enum KeyError: Error {
    case reason(String)

    struct Reason {
        static let emptyTag = KeyError.reason("The key's tag cannot be empty.")
        static let unknown = KeyError.reason("There was an unknown error.")
        static let couldNotCopyKey = KeyError.reason("Could not copy public key")
    }
}


struct KeyMaker {

    fileprivate static func createQuery(tag: String, type: CFString, name: String) throws -> [String: Any] {

        let tag = tag.data(using: .utf8)!
        return [kSecAttrKeyType as String:            type,
             kSecAttrKeySizeInBits as String:      2048,
             kSecAttrLabel as String: name as CFString,
             kSecPrivateKeyAttrs as String:
                [kSecAttrIsPermanent as String:    true,
                 kSecAttrApplicationTag as String: tag]
        ]

    }

    static func delete(symmetricKeyWith tag: String, type: CFString, name: String) throws -> Void {

        if tag.isEmpty == true {
            throw KeyError.Reason.emptyTag
        }

        let attr = try createQuery(tag: tag, type: type, name: name)
        let result = SecItemDelete(attr as CFDictionary)

        switch result {
        case errSecSuccess:
            break
        default:
            var error: Unmanaged<CFError>?
            SecCopyErrorMessageString(result, &error)

            guard let message = error?.takeRetainedValue().localizedDescription else {
                throw KeyError.Reason.unknown
            }

            throw KeyError.reason(message)
        }
    }

    static func generate(symmetricKeyWith tag: String, type: CFString = kSecAttrKeyTypeRSA, name: String) throws -> SecKey {

        if tag.isEmpty == true {
            throw KeyError.Reason.emptyTag
        }

        let attributes = try createQuery(tag: tag, type: type, name: name)

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        return privateKey
    }

    static func fetchPublicKey(tag: String, type: CFString, name: String) throws -> SecKey {


        if tag.isEmpty == true {
            throw KeyError.Reason.emptyTag
        }

        var item: CFTypeRef?
        let attr = try createQuery(tag: tag, type: type, name: name)
        let status = SecItemCopyMatching(attr as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            let secKey = item as! SecKey
            guard let pubKey = SecKeyCopyPublicKey(secKey) else {
                throw KeyError.Reason.couldNotCopyKey
            }
            return pubKey
        default:
            //Create a new key
            return try generate(symmetricKeyWith: tag, type: type, name: name)

        }
    }
}

extension KeyMaker {

    func getSupportedAlgorithms(publicKey: SecKey) -> [(algo: SecKeyAlgorithm, supported: Bool)] {

        typealias ReturnType = (algo: SecKeyAlgorithm, supported: Bool)

        var results: [ReturnType] = []


    }

    private func helper() -> [SecKeyAlgorithm] {
        return [

            SecKeyAlgorithm.ecdhKeyExchangeCofactor,
            .ecdhKeyExchangeCofactorX963SHA1,
            .ecdhKeyExchangeCofactorX963SHA224,
            .ecdhKeyExchangeCofactorX963SHA256,
            .ecdhKeyExchangeCofactorX963SHA384,
            .ecdhKeyExchangeCofactorX963SHA512,
            .ecdhKeyExchangeStandard,
            .ecdhKeyExchangeStandardX963SHA1,
            .ecdhKeyExchangeStandardX963SHA224,
            .ecdhKeyExchangeStandardX963SHA256,
            .ecdhKeyExchangeStandardX963SHA384,
            .ecdhKeyExchangeStandardX963SHA512,
            .ecdsaSignatureDigestX962,
            .ecdsaSignatureDigestX962SHA1,
            .ecdsaSignatureDigestX962SHA224,
            .ecdsaSignatureDigestX962SHA256,
            .ecdsaSignatureDigestX962SHA384,
            .ecdsaSignatureDigestX962SHA512,
            .ecdsaSignatureRFC4754,
            .eciesEncryptionCofactorVariableIVX963SHA224AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA384AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA512AESGCM,
            .eciesEncryptionCofactorX963SHA1AESGCM,
            .eciesEncryptionCofactorX963SHA224AESGCM,
            .eciesEncryptionCofactorX963SHA256AESGCM,
            .eciesEncryptionCofactorX963SHA384AESGCM,
            .eciesEncryptionCofactorX963SHA512AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA224AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA384AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA512AESGCM,
            .eciesEncryptionStandardVariableIVX963SHA224AESGCM,
            .eciesEncryptionStandardVariableIVX963SHA256AESGCM,
            .eciesEncryptionStandardVariableIVX963SHA384AESGCM,
            .eciesEncryptionStandardVariableIVX963SHA512AESGCM,
            .rsaEncryptionOAEPSHA1,
            .rsaSignatureDigestPSSSHA512,
            .rsaEncryptionPKCS1,
            .rsaSignatureDigestPKCS1v15SHA512,
            .rsaEncryptionRaw,
            .rsaSignatureRaw,
            .rsaEncryptionOAEPSHA224,
            .rsaEncryptionOAEPSHA224AESGCM,
            .rsaEncryptionOAEPSHA256,
            .rsaEncryptionOAEPSHA256AESGCM,
            .rsaEncryptionOAEPSHA384,
            .
        ]

    }
}
