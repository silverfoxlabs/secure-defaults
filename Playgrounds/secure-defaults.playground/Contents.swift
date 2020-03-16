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

let p = Settings()

let provider = UserDefaultsEncryption<Settings>(.rsa(SecKeyAlgorithm.rsaSignatureDigestPSSSHA512))

do {
    let val = try provider.encrypt(data: p)
    try p.save(encrypted: val)
}
catch {
    print(error)
}


//let p = Settings()
//
/////RSA Provider Encryption Example:
//let provider = RSAEncryption<Settings>()
//do {
//    let val = try provider.encrypt(data: p)
//    try p.save(encrypted: val)
//}
//catch {
//    print(error.localizedDescription)
//}
//
//var payload: String
//
//do {
//    payload = try Settings.encryptedData()
//    let result = try provider.decrypt(data: payload)
//    result.isUser //should be true
//}
//catch {
//    print(error.localizedDescription)
//}
//
//
/////ECDSA Provider Encryption Example:
//let ecProvider = ECDSAEncryption<Settings>(algorithm: SecKeyAlgorithm.ecdsaSignatureDigestX962SHA512, useSecureEnclave: false)
//
//do {
//    let val = try provider.encrypt(data: p)
//    try p.save(encrypted: val)
//}
//catch {
//    print(error.localizedDescription)
//}
//
//do {
//    payload = try Settings.encryptedData()
//    let result = try provider.decrypt(data: payload)
//    result.isUser // should be true
//}
//catch {
//    print(error.localizedDescription)
//}


