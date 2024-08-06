//
//  protocols.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import Foundation
import CryptoKit
import CryptoSwift

public class RatchetProtocols {
    static func DHRatchet(state: States, header: HEADERS, keystoreAlias: String? = nil) throws {
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        
        state.DHr = header.dh
        var sharedSecret = try DH(privateKey: state.DHs!, peerPublicKey: state.DHr!).withUnsafeBytes { data in
            return Array(data)
        }
        (state.RK, state.CKr) = try KDF_RK(rk: state.RK!, dh: sharedSecret)
        state.DHs = try GENERATE_DH(keystoreAlias: keystoreAlias)
        sharedSecret = try DH(privateKey: state.DHs!, peerPublicKey: state.DHr!).withUnsafeBytes { data in
            return Array(data)
        }
        (state.RK, state.CKs) = try KDF_RK(rk: state.RK!, dh: sharedSecret)
    }

    static func GENERATE_DH(keystoreAlias: String? = nil) throws -> Curve25519.KeyAgreement.PrivateKey {
        let (privateKey, secKey) = try SecurityCurve25519.generateKeyPair(keystoreAlias: keystoreAlias)
        return privateKey
    }
    
    static func DH(privateKey: Curve25519.KeyAgreement.PrivateKey,
                   peerPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> [UInt8] {
        return try SecurityCurve25519.calculateSharedSecret(
            privateKey: privateKey, publicKey: peerPublicKey).withUnsafeBytes { data in
                return Array(data)
            }
    }
    
    
    static func KDF_RK(rk: [UInt8], dh: [UInt8]) throws -> (rk: [UInt8], ck: [UInt8]) {
        let info = "KDF_RK"
        
        return try HKDF(
            password: dh,
            salt: rk,
            info: info.bytes,
            keyLength: 32*2, variant: .sha2(.sha512))
            .calculate().withUnsafeBytes {
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
    
    
    static func ENCRYPT(mk: [UInt8], 
                        plainText: [UInt8],
                        associatedData: [UInt8]) throws -> [UInt8]{
        let (key, authKey, iv) = try CryptoHelper.getCipherMACParameters(mk: mk)
        
        let cipherText = try AES(
            key: key,
            blockMode: CBC(iv: iv),
            padding: .pkcs7).encrypt(plainText)
        
        let mac = try CryptoHelper.buildVerificationHash(
            authKey: authKey,
            associatedData: associatedData,
            cipherText: cipherText)
        
        return cipherText + mac
    }
    
    
    static func DECRYPT(mk: [UInt8],
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
