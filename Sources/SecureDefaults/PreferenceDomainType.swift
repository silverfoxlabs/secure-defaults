//
//  PreferenceDomainType.swift
//  SecureDefaults
//
//  Created by Benedetto on 3/11/20.
//

import Foundation

public protocol PreferenceDomainType {
    
    associatedtype EncryptedData
    
    /// The name of your PreferenceDomainType
    /// - Note: Generally you will want to use a
    /// a reverse domain style string.  This value
    /// will be used to register with the UserDefaults.
    static var name: String { get }
    /// The key to use for the defaults dictionary
    static var key: String { get }
    /// Tag for Keychain Storage & Retrieval
    static var tag: String { get }
    /// Registers your PreferenceDomain with the User Defaults
    /// - Note: Uses the 'key' var as your key, with a String value
    /// ie: ["myPreferenceKey" : "some hashed value"]
    /// - Returns: Void
    func register() throws -> Void
    /// Saving the preference domain type to the suite
    ///
    /// - Parameter input: an encrypted string of the PreferenceDomainType
    /// - Returns: Void
    func save(encrypted data: EncryptedData) throws -> Void
    /// Retrieving the encrypted Payload
    /// - Note: The default implementation retrieves the payload from the suite
    /// using the key.
    /// - Returns: A String value representing the encrypted payload.
    static func encryptedData() throws -> EncryptedData
}

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
