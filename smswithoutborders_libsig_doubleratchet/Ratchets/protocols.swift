//
//  protocols.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import Foundation
import CryptoKit

class DHRatchet {
    init() {
        
    }
    
    
    static func GENERATE_DH(keystoreAlias: String) throws -> Curve25519.KeyAgreement.PrivateKey {
        let (privateKey, secKey) = try SecurityCurve25519.generateKeyPair(keystoreAlias: keystoreAlias)
        return privateKey
    }
    
    static func DH(privateKey: Curve25519.KeyAgreement.PrivateKey,
                   peerPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> SymmetricKey {
        return try SecurityCurve25519.calculateSharedSecret(
            privateKey: privateKey, publicKey: peerPublicKey)
    }
    
    
    static func KDF_RK(rk: SharedSecret,
                       publicKey: Curve25519.KeyAgreement.PublicKey) throws -> SymmetricKey {
        let info = "KDF_RK"
        return rk.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: info.data(using: .utf8)!,
                outputByteCount: 32)
    }
    
    
    static func KDF_CK(ck: SymmetricKey) -> (ck: Data, rk: Data){
        let _ck = HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: ck)
        let mk = HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: ck)
        return (Data(_ck), Data(mk))
    }
    
    
    static func ENCRYPT(mk: Data, plainText: String, associatedData: String) {
        let hkdfOutput = CryptoHelper.getCipherMACParameters(mk: mk)
        let key = hkdfOutput.prefix(32)
        let range = 32..<64
        let authenticationKey = hkdfOutput.subdata(in: range)
        let iv = 64..<(64+16)
        
    }
    
    
    static func DECRYPT() {
        
    }
    
    
    static func CONCAT() {
        
    }
}
