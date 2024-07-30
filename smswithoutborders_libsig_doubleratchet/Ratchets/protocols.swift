//
//  protocols.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import Foundation
import CryptoKit
import CryptoSwift

class DHRatchet {
    
    static func GENERATE_DH(keystoreAlias: String) throws -> Curve25519.KeyAgreement.PrivateKey {
        let (privateKey, secKey) = try SecurityCurve25519.generateKeyPair(keystoreAlias: keystoreAlias)
        return privateKey
    }
    
    static func DH(privateKey: Curve25519.KeyAgreement.PrivateKey,
                   peerPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> SymmetricKey {
        return try SecurityCurve25519.calculateSharedSecret(
            privateKey: privateKey, publicKey: peerPublicKey)
    }
    
    
    static func KDF_RK(rk: SharedSecret, _dh: SymmetricKey) throws -> (rk: [UInt8], ck: [UInt8]) {
        let dh = _dh.withUnsafeBytes {
            Data(Array($0))
        }
        let info = "KDF_RK"
        return rk.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: dh,
            sharedInfo: info.data(using: .utf8)!,
            outputByteCount: 32*2).withUnsafeBytes {
                return (Array(Array($0)[0..<32]), Array(Array($0)[32..<64]))
            }
    }
    
    
    static func KDF_CK(ck: [UInt8]) throws  -> (ck: [UInt8], rk: [UInt8]){
        let bytes1: [UInt8] = [0x01]
        let bytes2: [UInt8] = [0x02]
        
        let _ck = try HMAC(key: ck, 
                           variant: .sha2(.sha256)).authenticate(bytes1)
        let mk = try HMAC(key: ck, 
                          variant: .sha2(.sha256)).authenticate(bytes2)
//        return (Data(_ck), Data(mk))
        
        return (_ck, mk)
    }
    
    
    static func ENCRYPT(mk: Data, 
                        plainText: String,
                        associatedData: [UInt8]) throws -> (cipherText: [UInt8], 
                                                            mac: [UInt8]){
        let (key, authKey, iv) = try CryptoHelper.getCipherMACParameters(mk: mk)
        
        let cipherText = try AES(
            key: key,
            blockMode: CBC(iv: iv),
            padding: .pkcs7).encrypt(Array(plainText.utf8))
        
        let mac = try CryptoHelper.buildVerificationHash(
            authKey: authKey,
            associatedData: associatedData,
            cipherText: cipherText)
        
        return (cipherText, mac)
    }
    
    
    static func DECRYPT(mk: Data,
                        cipherText: [UInt8],
                        associatedData: [UInt8]) throws -> [UInt8]{
        let cipherText = try CryptoHelper.verifyCipherText(
            mk: mk, _mac: cipherText, associatedData: associatedData)
        
        let (key, authKey, iv) = try CryptoHelper.getCipherMACParameters(mk: mk)
        
        return try AES(
            key: key,
            blockMode: CBC(iv: iv),
            padding: .pkcs7).decrypt(cipherText)
    }
    
    
    static func CONCAT(AD: [UInt8], headers: HEADERS) throws -> [UInt8] {
        return AD + headers.serialize()
    }
}
