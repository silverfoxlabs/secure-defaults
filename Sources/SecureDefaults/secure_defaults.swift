
import Foundation
import Security



public extension PreferenceDomainType where Self : Codable, Self.EncryptedData == String {

    func register() throws -> Void {
        
        UserDefaults.standard.addSuite(named: Self.name)
        
        guard let s = UserDefaults(suiteName: Self.name) else {
            throw EncryptionProviderError.failure(reason: "Could not retrieve custom suite.")
        }
        
        s.register(defaults: [Self.key: NSNull()])
    }
    
    func save(encrypted data: EncryptedData) throws -> Void {
        let suite = UserDefaults(suiteName: Self.name)
        suite?.set(data, forKey: Self.key)
        suite?.synchronize()
        UserDefaults.standard.synchronize()
    }
    
    static func encryptedData() throws -> EncryptedData {

        guard let suite = UserDefaults(suiteName: Self.name) else {
            throw EncryptionProviderError.failedDecryption(reason: "Could Not Do it")
        }

        guard let data = suite.string(forKey: Self.key) else {
            throw EncryptionProviderError.failedDecryption(reason: "Could not find key in UserDefaults")
        }
        
        return data
    }
}
