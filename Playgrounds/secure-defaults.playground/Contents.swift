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

//let provider = RSAEncryption<Prefs>()
//try! provider.nuke()
//var val = try! provider.encrypt(input: p)
//p.save(encryptedPayload: val)

//let ecdsaProvider = ECDSAEncryption<Prefs>()
//try! ecdsaProvider.nuke()
//let _val = try! ecdsaProvider.encrypt(input: p)
//p.save(encryptedPayload: _val)

