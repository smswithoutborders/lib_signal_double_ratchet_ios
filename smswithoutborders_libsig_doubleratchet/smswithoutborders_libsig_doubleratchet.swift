//
//  smswithoutborders_libsig_doubleratchet.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import CryptoKit

class smswithoutborders_libsig_doubleratchet {
    static func aliceInit(state: States,
                          SK: SharedSecret,
                          bobDhPubKey: Curve25519.KeyAgreement.PublicKey,
                          keystoreAlias: String) throws {
        state.DHs = try DHRatchet.GENERATE_DH(keystoreAlias: keystoreAlias)
        state.DHr = bobDhPubKey
        (state.RK, state.CKs) = try DHRatchet.KDF_RK(rk: SK,
            dh: try DHRatchet.DH(privateKey: state.DHs!, peerPublicKey: state.DHr!))
        state.CKr = nil
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = [:]
    }
    
    static func bobInit(state: States, SK: [UInt8], bobKeyPair: Curve25519.KeyAgreement.PrivateKey) {
        state.DHs = bobKeyPair
        state.DHr = nil
        state.RK = SK
        state.CKs = nil
        state.CKr = nil
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = [:]
    }
    
    func encrypt(state: States, data: [UInt8], AD: [UInt8]) throws -> (header: HEADERS, cipherText: [UInt8]) {
        var mk: [UInt8]
        (state.CKs, mk) = try DHRatchet.KDF_CK(ck: state.CKs!)
        let header = HEADERS(dhPair: state.DHs!.publicKey, PN: UInt32(state.PN), N: UInt32(state.Ns))
        state.Ns += 1
        return (header,
                try DHRatchet.ENCRYPT(
                    mk: mk,
                    plainText: data,
                    associatedData: DHRatchet.CONCAT(AD: AD, headers: header)))
    }
    
    func decrypt() {
        
    }
    
    func trySkippedMessageKeys() {
        
    }
    
    func skipMessageKeys() {
        
    }
}
