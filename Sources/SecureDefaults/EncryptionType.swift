//
//  EncryptionType.swift
//  SecureDefaults
//
//  Created by David Cilia on 3/15/20.
//

import Foundation

public enum EncryptionType {
    case rsa(SecKeyAlgorithm), ecdsa(SecKeyAlgorithm)

    public func values() -> (CFString, SecKeyAlgorithm) {
        switch self {
        case .rsa(let t):
            return (kSecAttrKeyTypeRSA, t)
        case .ecdsa(let t):
            return (kSecAttrKeyTypeEC, t)

        }
    }
}
