//: Playground - noun: a place where people can play

import Cocoa

var str = "Hello, playground"

//Creating an Asymmetric Key Pair
let tag = "com.example.keys.mykey".data(using: .utf8)!
let attributes : [String : Any] = [

    kSecAttrKeyType as String : kSecAttrKeyTypeECDSA,
    kSecAttrKeySizeInBits as String : 2048,
    kSecPrivateKeyAttrs as String : [

        kSecAttrIsPermanent as String : true,
        kSecAttrApplicationTag as String : tag,
    ],

    kSecPublicKeyAttrs as String : [
        kSecAttrIsPermanent as String : false,
    ]
]

//Only tag the private key, and create the public key from the private one when you need it.  No need to clutter the keychain with tags.

var error : Unmanaged<CFError>?

let result = SecItemDelete(attributes as CFDictionary)
if result == errSecSuccess {
    print("Success!")
}
else {
    print("Failure")
}

var pri : UnsafeMutablePointer<SecKey?>?
var pub : UnsafeMutablePointer<SecKey?>?

SecKeyGeneratePair(attributes as CFDictionary, pub, pri)


let privateKey : SecKey = pri!.pointee!
let publicKey : SecKey? = pub?.pointee

//guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
//
//    throw error!.takeRetainedValue() as Error
//}
//
//let publicKey = SecKeyCopyPublicKey(privateKey)

let data = "hello".data(using: .utf8)!


func supported(key : SecKey) -> SecKeyAlgorithm {

    let keys : [SecKeyAlgorithm] = [
        SecKeyAlgorithm.rsaEncryptionPKCS1,
        .rsaSignatureRaw,
        .rsaSignatureDigestPSSSHA512,
        .rsaSignatureMessagePSSSHA512,
        .rsaSignatureDigestPKCS1v15SHA512,
        .rsaEncryptionRaw,
        .rsaEncryptionPKCS1,
        .rsaSignatureDigestPSSSHA512,
        .rsaSignatureDigestPKCS1v15SHA512,
        .rsaEncryptionOAEPSHA1,
        .rsaEncryptionOAEPSHA224,
        .rsaSignatureMessagePSSSHA1,
        .rsaSignatureMessagePSSSHA224,
        .ecdhKeyExchangeCofactor,
        .ecdsaSignatureRFC4754,
        .ecdsaSignatureDigestX962SHA512,
        .ecdhKeyExchangeStandardX963SHA512,
        .eciesEncryptionStandardX963SHA512AESGCM
    ]

    var algo = SecKeyAlgorithm.rsaEncryptionPKCS1

    keys.forEach {
        if SecKeyIsAlgorithmSupported(key, SecKeyOperationType.encrypt, $0) == true {

            print($0)
            algo = $0
        }
    }

    return algo
}

//let algo = supported(key: publicKey!)
let algo = SecKeyAlgorithm.rsaEncryptionOAEPSHA512

guard let signed = SecKeyCreateEncryptedData(publicKey!, algo, data as CFData, &error) else {
    throw error!.takeRetainedValue() as Error
}

print(signed)

guard let unsigned = SecKeyCreateDecryptedData(privateKey, algo, signed, &error) else {
    throw error!.takeRetainedValue() as Error
}

let decryptedStr = String(data: unsigned as Data, encoding: .utf8)
print(decryptedStr ?? "bah!")

//import SecureDefaults
//
//class Prefs : Codable {
//
//    var name : String = "Luke"
//    var last = "Skywalker"
//    var lastOpen = Date()
//    var isUser = false
//}
//
//extension Prefs : PreferenceDomainType {
//
//    static var key: String {
//        return "settings"
//    }
//
//    static var name: String {
//        return "Test Key Can Delete"
//    }
//
//    static var tag: String {
//        return "preferences.com.tags"
//    }
//}
//
//var p = Prefs()
//p.isUser = true
//
/////RSA Provider Encryption Example:
//let provider = RSAEncryption<Prefs>()
//do {
//    let val = try provider.encrypt(input: p)
//    p.save(encryptedPayload: val)
//}
//catch {
//    print(error.localizedDescription)
//}
//
//var payload : String = ""
//
//do {
//    payload = try Prefs.encryptedPayload()
//    let result = try provider.decrypt(input: payload)
//    result.isUser //should be true
//}
//catch {
//    print(error.localizedDescription)
//}
//
//
/////ECDSA Provider Encryption Example:
//let ecProvider = ECDSAEncryption<Prefs>()
//
//do {
//    let val = try provider.encrypt(input: p)
//    p.save(encryptedPayload: val)
//}
//catch {
//    print(error.localizedDescription)
//}
//
//do {
//    payload = try! Prefs.encryptedPayload()
//    let result = try provider.decrypt(input: payload)
//    result.isUser // should be true
//}
//catch {
//    print(error.localizedDescription)
//}


