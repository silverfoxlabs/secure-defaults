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

let provider = UserDefaultsEncryption<Settings>(.ecdsa(.eciesEncryptionCofactorX963SHA256AESGCM))

do {
    let val = try provider.encrypt(data: p)
    try p.save(encrypted: val)
}
catch {
    print(error)
}
 
