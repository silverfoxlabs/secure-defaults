
import Foundation
import Security


public struct Reasons {
    static let couldNotCopyPublicKey = "Could not copy the public key"
    static let couldNotCopySecureEnclave = "Could not generate EC keys using the Secure Enclave"
    static let failedEncryption = "SecKeyGeneratePair did not return a public key for the EC key generation with the Secure Enclave."
    static let failGetPublicKey = "Could not get public key."
    static let unknownError = "Unknown Error"
}

public enum EncryptionProviderError : Error {
    
    case failure(reason: String)
    case failedEncryption(reason: String)
    case failedDecryption(reason : String)
    case couldNotRetrieveKey
    case couldNotDeleteKeys
    case inputError
}

public protocol EncryptionProvider {
    
    associatedtype Domain
    associatedtype EncryptedType
    
    var attributesPublic : [ String : Any] { get }
    var attributesPrivate : [String : Any] { get }
    func encrypt(input: Domain) throws -> EncryptedType
    func decrypt(input: EncryptedType) throws -> Domain
    func nuke() throws -> Void

}

public protocol PreferenceDomainType {
    /// The name of your PreferenceDomainType
    /// - Note: Generally you will want to use a
    /// a reverse domain style string.  This value
    /// will be used to register with the UserDefaults.
    static var name : String { get }
    /// The key to use for the defaults dictionary
    static var key : String { get }
    /// Tag for Keychain Storage & Retrieval
    static var tag : String { get }
    /// Registers your PreferenceDomain with the User Defaults
    /// - Note: Uses the 'key' var as your key, with a String value
    /// ie: ["myPreferenceKey" : "some hashed value"]
    /// - Returns: Void
    func register() -> Void
    /// Saving the preference domain type to the suite
    ///
    /// - Parameter input: an encrypted string of the PreferenceDomainType
    /// - Returns: Void
    func save(encryptedPayload : String) -> Void
    /// Retrieving the encrypted Payload
    /// - Note: The default implementation retrieves the payload from the suite
    /// using the key.
    /// - Returns: A String value representing the encrypted payload.
    static func encryptedPayload() -> String
}

public extension PreferenceDomainType where Self : Codable {

    func register() -> Void {
        UserDefaults.standard.addSuite(named: Self.name)
        let suite = UserDefaults(suiteName: Self.name)
        suite?.register(defaults: [Self.key : ""])
    }
    
    func save(encryptedPayload: String) -> Void {
        let suite = UserDefaults(suiteName: Self.name)
        suite?.set(encryptedPayload, forKey: Self.key)
        suite?.synchronize()
        UserDefaults.standard.synchronize()
    }
    
    static func encryptedPayload() -> String {
        let suite = UserDefaults(suiteName: Self.name)
        return suite?.string(forKey: Self.key) ?? ""

    }

    typealias RawData = String
    static func fetch() throws -> RawData {

        guard let suite = UserDefaults(suiteName: Self.name) else {
            throw EncryptionProviderError.failedDecryption(reason: "Could Not Do it")
        }

        guard let data = suite.string(forKey: Self.key) else {
            
        }
    }
}

