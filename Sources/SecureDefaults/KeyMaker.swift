//
//  KeyMaker.swift
//  SecureDefaults
//
//  Created by David Cilia on 3/14/20.
//

import Foundation


public enum KeyError: Error {
    struct Reason {
        static let emptyTag = KeyError.reason("The key's tag cannot be empty.")
        static let unknown = KeyError.reason("There was an unknown error.")
        static let couldNotCopyKey = KeyError.reason("Could not copy public key")
    }

    case reason(String)
}


public struct KeyMaker {

    public typealias PrivateKey = SecKey
    public typealias PublicKey = SecKey

    fileprivate static func fetchQuery(tag: String,
                                       type: CFString,
                                       name: String) throws -> [String: Any] {

        let _tag = tag.data(using: .utf8)!
        let getquery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: type,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecPrivateKeyAttrs as String: [
                kSecAttrApplicationTag as String: _tag as CFData,
                kSecAttrLabel as String: name as CFString,
            ]
        ]

        return getquery

    }

    fileprivate static func createQuery(tag: String,
                                        type: CFString,
                                        name: String,
                                        size: Int) throws -> [String: Any] {



        let tag = tag.data(using: .utf8)!
        let attributes: [String: Any] = [

            kSecAttrKeyType as String: type,
            kSecAttrKeySizeInBits as String: size,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrLabel as String: name,
            ]
        ]
        return attributes
    }


    public static func delete(keyWith tag: String,
                              type: CFString,
                              name: String) throws -> Void {

        if tag.isEmpty == true {
            throw KeyError.Reason.emptyTag
        }

        let attr = try fetchQuery(tag: tag,
                                  type: type,
                                  name: name)
        
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

    public static func generate(keyWith tag: String,
                                type: CFString = kSecAttrKeyTypeRSA,
                                name: String, size: Int) throws -> PrivateKey {

        if tag.isEmpty == true {
            throw KeyError.Reason.emptyTag
        }

        let attributes = try createQuery(tag: tag,
                                         type: type,
                                         name: name,
                                         size: size)
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return privateKey
    }

    public static func fetch(keyWith tag: String,
                             type: CFString,
                             name: String, size: Int = 2048) throws -> PrivateKey {

        if tag.isEmpty == true {
            throw KeyError.Reason.emptyTag
        }

        var item: CFTypeRef?
        let attr = try fetchQuery(tag: tag, type: type, name: name)
        let status = SecItemCopyMatching(attr as CFDictionary, &item)

        var privateKey: SecKey
        
        switch status {
        case errSecSuccess: //Found key
            print("found key")
            if item == nil {
                privateKey = try generate(keyWith: tag,
                                          type: type,
                                          name: name,
                                          size: size)
            }
            else {
                privateKey = item as! SecKey
            }
        default:
            //Create a new key
            print("generate new key")
            privateKey = try generate(keyWith: tag,
                                      type: type,
                                      name: name,
                                      size: size)
        }

        return privateKey
    }

    public static func getPublicKey(key: PrivateKey) throws -> PublicKey {

        guard let k = SecKeyCopyPublicKey(key) else {
            throw KeyError.Reason.couldNotCopyKey
        }

        return k
    }
}
