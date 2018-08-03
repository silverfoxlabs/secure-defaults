//
//  EncryptionProvider.swift
//  SecureDefaults
//
//  Created by Benedetto on 8/1/18.
//

import Foundation

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
    associatedtype Algorithm

    var algorithm : Algorithm { get set }
    var attributesPublic : [ String : Any] { get }
    var attributesPrivate : [String : Any] { get }
    func encrypt(input: Domain) throws -> EncryptedType
    func decrypt(input: EncryptedType) throws -> Domain
    func nuke() throws -> Void
    
}
