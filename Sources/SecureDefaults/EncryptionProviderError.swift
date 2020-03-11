//
//  EncryptionProviderError.swift
//  SecureDefaults
//
//  Created by Benedetto on 3/11/20.
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

public struct Reasons {
    static let couldNotCopyPublicKey = "Could not copy the public key"
    static let couldNotCopySecureEnclave = "Could not generate EC keys using the Secure Enclave"
    static let failedEncryption = "SecKeyGeneratePair did not return a public key for the EC key generation with the Secure Enclave."
    static let failGetPublicKey = "Could not get public key."
    static let unknownError = "Unknown Error"
}
