//: Playground - noun: a place where people can play

import SecureDefaults
import Foundation

class Settings : Codable {
    
    var name : String = "Tom"
    var last = "Beringer"
    var lastOpen = Date()
    var isUser = true
}

extension Settings : PreferenceDomainType {
    
    typealias EncryptedData = String
    
    static var key: String {
        return "settings"
    }
    
    static var name: String {
        return "appSettings"
    }
    
    static var tag: String {
        return "com.app.\(key)"
    }
}

let settings = Settings()
let provider = UserDefaultsEncryption<Settings>(EncryptionType.rsa(.rsaEncryptionOAEPSHA512AESGCM))

do {

    let encrypted = try provider.encrypt(data: settings)
    let _ = try settings.save(encrypted: encrypted)


    let encData = try Settings.encryptedData()
    let s = try provider.decrypt(data: encData)
    print(s)
}
catch {
    print(error.localizedDescription)
}



//typealias PrivateKey = SecKey
//typealias PublicKey = SecKey
//
//
//func create(tag: String, type: CFString = kSecAttrKeyTypeRSA) throws -> PrivateKey {
//
//
//    let size: Int
//    switch type {
//    case kSecAttrKeyTypeRSA:
//        size = 2048
//    default:
//        size = 256
//    }
//
//    print(size)
//
//    let tag = tag.data(using: .utf8)!
//    let attributes: [String: Any] =
//        [kSecAttrKeyType as String:            type,
//         kSecAttrKeySizeInBits as String:      size,
//         kSecPrivateKeyAttrs as String:
//            [kSecAttrIsPermanent as String:    true,
//             kSecAttrApplicationTag as String: tag,
//             kSecAttrLabel as String: "SecureDefaults"]
//    ]
//
//    var error: Unmanaged<CFError>?
//    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
//        throw error!.takeRetainedValue() as Error
//    }
//
//    return privateKey
//}
//
//enum KeyError: Error {
//    case couldNotCreatePublicKey
//
//    var localizedDescription: String {
//        switch self {
//        case .couldNotCreatePublicKey:
//            return "Could not create a public key from the private key."
//        }
//    }
//}
//
//func create(publicKeyWith privateKey: PrivateKey) throws -> PublicKey {
//
//    guard let pKey = SecKeyCopyPublicKey(privateKey) else {
//        throw KeyError.couldNotCreatePublicKey
//    }
//
//    return pKey
//}
//
//let key = try? create(tag: Settings.tag, type: kSecAttrKeyTypeECSECPrimeRandom)
//let pKey = try? create(publicKeyWith: key!)
//
//let data = "Hello World".data(using: .utf8)!
//var error: Unmanaged<CFError>?
//let encrypted = SecKeyCreateEncryptedData(pKey!, .eciesEncryptionCofactorX963SHA512AESGCM, data as CFData, &error)
//
//if error != nil {
//    print(error!.takeRetainedValue().localizedDescription)
//}
//
//let decrypted = SecKeyCreateDecryptedData(key!, .eciesEncryptionCofactorX963SHA512AESGCM, encrypted!, &error)
//
//let str = String(data: decrypted! as Data, encoding: .utf8)
//
//print(str)




//
//let res0 = SecKey.getSupportedAlgorithms(publicKey: key!, operation: .encrypt)
//
//res0.forEach { print("\($0.0) = \($0.1)")}
//
//
//print("---------------------------\n\n\n\n")
//
//
//let res = SecKey.getSupportedAlgorithms(publicKey: key!, operation: .decrypt)
//
//res.forEach { print("\($0.0) = \($0.1)")}
//



//let tag = "com.example.keys.mykey".data(using: .utf8)!
//let addquery: [String: Any] = [kSecClass as String: kSecClassKey,
//                               kSecAttrApplicationTag as String: tag,
//                               kSecValueRef as String: key]
 
