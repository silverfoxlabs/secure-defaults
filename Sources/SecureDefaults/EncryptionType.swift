//
//  EncryptionType.swift
//  SecureDefaults
//
//  Created by David Cilia on 3/15/20.
//

import Foundation

public enum EncryptionType {

    case rsa(SecKeyAlgorithm, Int = 2048)
    case ecdsa(SecKeyAlgorithm, Int = 256)
    case other(CFString, SecKeyAlgorithm, Int)

    public func values() -> (CFString, SecKeyAlgorithm, Int) {
        switch self {
        case .rsa(let t, let s):
            return (kSecAttrKeyTypeRSA, t, s)
        case .ecdsa(let t, let s):
            return (kSecAttrKeyTypeECSECPrimeRandom, t, s)
        case .other(let a, let b, let c):
            return (a, b, c)
        }
    }
}
