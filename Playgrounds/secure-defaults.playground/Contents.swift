//: Playground - noun: a place where people can play

import Cocoa

var str = "Hello, playground"

import SecureDefaults

class Settings : Codable {
    
    var name : String = "Tom"
    var last = "Beringer"
    var lastOpen = Date()
    var isUser = true
}

extension Settings : PreferenceDomainType {
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

///RSA Provider Encryption Example:
let provider = RSAEncryption<Settings>()
do {
    let val = try provider.encrypt(input: p)
    p.save(encryptedPayload: val)
}
catch {
    print(error.localizedDescription)
}

var payload = Settings.encryptedPayload()

do {
    let result = try provider.decrypt(input: payload)
    result.isUser //should be true
}
catch {
    print(error.localizedDescription)
}


///ECDSA Provider Encryption Example:
let ecProvider = ECDSAEncryption<Settings>()

do {
    let val = try provider.encrypt(input: p)
    p.save(encryptedPayload: val)
}
catch {
    print(error.localizedDescription)
}

payload = Settings.encryptedPayload()
do {
    let result = try provider.decrypt(input: payload)
    result.isUser // should be true
}
catch {
    print(error.localizedDescription)
}


