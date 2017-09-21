//: Playground - noun: a place where people can play

import Cocoa

var str = "Hello, playground"

import secure_defaults

class Prefs : Codable {
    
    var name : String = "Tom"
    var last = "Beringer"
    var lastOpen = Date()
    var isUser = true
}

extension Prefs : PreferenceDomainType {
    static var key: String {
        return "settings"
    }
    
    static var name: String {
        return "Test Key Can Delete"
    }
    
    static var tag: String {
        return "preferences.com.tags"
    }
}

let p = Prefs()

///RSA Provider Encryption Example:
let provider = RSAEncryption<Prefs>()
do {
    let val = try provider.encrypt(input: p)
    p.save(encryptedPayload: val)
}
catch {
    print(error.localizedDescription)
}

var payload = Prefs.encryptedPayload()

do {
    let result = try provider.decrypt(input: payload)
    result.isUser //should be true
}
catch {
    print(error.localizedDescription)
}


///ECDSA Provider Encryption Example:
let ecProvider = ECDSAEncryption<Prefs>()

do {
    let val = try provider.encrypt(input: p)
    p.save(encryptedPayload: val)
}
catch {
    print(error.localizedDescription)
}

payload = Prefs.encryptedPayload()
do {
    let result = try provider.decrypt(input: payload)
    result.isUser // should be true
}
catch {
    print(error.localizedDescription)
}


