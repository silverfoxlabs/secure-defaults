//
//  SecKeyHelper.swift
//  SecureDefaults
//
//  Created by David Cilia on 3/17/20.
//

import Foundation

extension SecKey {

    public static func getSupportedAlgorithms(publicKey: SecKey, operation: SecKeyOperationType, showSupportedOnly: Bool = false) -> [(SecKeyAlgorithm,Bool)] {

        typealias ReturnType = (SecKeyAlgorithm, Bool)

        var results: [ReturnType] = []
        let algos = helper()

        for i in 0..<algos.endIndex {

            let supported = SecKeyIsAlgorithmSupported(publicKey, operation, algos[i])


            if showSupportedOnly == true {

                if supported == true {
                    results.append((algos[i], supported))
                }
            }
            else {

                results.append((algos[i], supported))
            }
        }

        return results

    }

    static private func helper() -> [SecKeyAlgorithm] {
        return [

            //Elliptic Curve Key Exchange
            SecKeyAlgorithm.ecdhKeyExchangeCofactor,
            .ecdhKeyExchangeCofactorX963SHA1,
            .ecdhKeyExchangeCofactorX963SHA224,
            .ecdhKeyExchangeCofactorX963SHA256,
            .ecdhKeyExchangeCofactorX963SHA384,
            .ecdhKeyExchangeCofactorX963SHA512,
            //Elliptic Curve Key Exchange
            .ecdhKeyExchangeStandard,
            .ecdhKeyExchangeStandardX963SHA1,
            .ecdhKeyExchangeStandardX963SHA224,
            .ecdhKeyExchangeStandardX963SHA256,
            .ecdhKeyExchangeStandardX963SHA384,
            .ecdhKeyExchangeStandardX963SHA512,
            //Elliptic Curve Signature Digest X962
            .ecdsaSignatureDigestX962,
            .ecdsaSignatureDigestX962SHA1,
            .ecdsaSignatureDigestX962SHA224,
            .ecdsaSignatureDigestX962SHA256,
            .ecdsaSignatureDigestX962SHA384,
            .ecdsaSignatureDigestX962SHA512,
            //Elliptic Curve Signature Message X962
            .ecdsaSignatureMessageX962SHA1,
            .ecdsaSignatureMessageX962SHA224,
            .ecdsaSignatureMessageX962SHA256,
            .ecdsaSignatureMessageX962SHA384,
            .ecdsaSignatureMessageX962SHA512,
            //Elliptic Curve Key Exchange
            .ecdhKeyExchangeStandard,
            .ecdhKeyExchangeCofactor,
            .ecdhKeyExchangeCofactorX963SHA1,
            .ecdhKeyExchangeCofactorX963SHA224,
            .ecdhKeyExchangeCofactorX963SHA256,
            .ecdhKeyExchangeCofactorX963SHA384,
            .ecdhKeyExchangeCofactorX963SHA512,
            .ecdhKeyExchangeStandardX963SHA1,
            .ecdhKeyExchangeStandardX963SHA224,
            .ecdhKeyExchangeStandardX963SHA256,
            .ecdhKeyExchangeStandardX963SHA384,
            .ecdhKeyExchangeStandardX963SHA512,
            //Ellliptic Curve Signature RFC4754
            .ecdsaSignatureRFC4754,
            //Elliptic Curve Encryption Standard X963
            .eciesEncryptionStandardX963SHA1AESGCM,
            .eciesEncryptionStandardX963SHA224AESGCM,
            .eciesEncryptionStandardX963SHA256AESGCM,
            .eciesEncryptionStandardX963SHA384AESGCM,
            .eciesEncryptionStandardX963SHA512AESGCM,
            //Elliptic Curve Encryption Cofactor X963
            .eciesEncryptionCofactorX963SHA1AESGCM,
            .eciesEncryptionCofactorX963SHA224AESGCM,
            .eciesEncryptionCofactorX963SHA256AESGCM,
            .eciesEncryptionCofactorX963SHA384AESGCM,
            .eciesEncryptionCofactorX963SHA512AESGCM,
            //Elliptic Curve Encryption Cofactor Variable IVX963
            .eciesEncryptionCofactorVariableIVX963SHA224AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA384AESGCM,
            .eciesEncryptionCofactorVariableIVX963SHA512AESGCM,
            //Elliptic Curve Encryption Standard Variable IVX963
            .eciesEncryptionStandardVariableIVX963SHA224AESGCM,
            .eciesEncryptionStandardVariableIVX963SHA256AESGCM,
            .eciesEncryptionStandardVariableIVX963SHA384AESGCM,
            .eciesEncryptionStandardVariableIVX963SHA512AESGCM,
            //RSA Encryption
            .rsaEncryptionRaw,
            .rsaEncryptionPKCS1,
            //RSA Encryption OAEP
            .rsaEncryptionOAEPSHA1,
            .rsaEncryptionOAEPSHA224,
            .rsaEncryptionOAEPSHA256,
            .rsaEncryptionOAEPSHA384,
            .rsaEncryptionOAEPSHA512,
            //RSA Encryption OAEP AESGCM
            .rsaEncryptionOAEPSHA1AESGCM,
            .rsaEncryptionOAEPSHA224AESGCM,
            .rsaEncryptionOAEPSHA256AESGCM,
            .rsaEncryptionOAEPSHA384AESGCM,
            .rsaEncryptionOAEPSHA512AESGCM,
            //RSA Signature Raw
            .rsaSignatureRaw,
            //RSA Signature Digest PKCS1v15
            .rsaSignatureDigestPKCS1v15Raw,
            .rsaSignatureDigestPKCS1v15SHA1,
            .rsaSignatureDigestPKCS1v15SHA224,
            .rsaSignatureDigestPKCS1v15SHA256,
            .rsaSignatureDigestPKCS1v15SHA384,
            .rsaSignatureDigestPKCS1v15SHA512,
            //RSA Signature Message PKCS1v15
            .rsaSignatureMessagePKCS1v15SHA1,
            .rsaSignatureMessagePKCS1v15SHA224,
            .rsaSignatureMessagePKCS1v15SHA256,
            .rsaSignatureMessagePKCS1v15SHA384,
            .rsaSignatureMessagePKCS1v15SHA512,
            //RSA Signate Digest PSS
            .rsaSignatureDigestPSSSHA1,
            .rsaSignatureDigestPSSSHA224,
            .rsaSignatureDigestPSSSHA256,
            .rsaSignatureDigestPSSSHA384,
            .rsaSignatureDigestPSSSHA512,
            //RSA Signature Message PSS
            .rsaSignatureMessagePSSSHA1,
            .rsaSignatureMessagePSSSHA224,
            .rsaSignatureMessagePSSSHA256,
            .rsaSignatureMessagePSSSHA384,
            .rsaSignatureMessagePSSSHA512
        ]
    }
}
