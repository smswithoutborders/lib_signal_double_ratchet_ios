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
                                                 _dh: try DHRatchet.DH(privateKey: state.DHs!, peerPublicKey: state.DHr!))
        state.DHr = bobDhPubKey
        state.DHr = bobDhPubKey
        state.DHr = bobDhPubKey
        state.DHr = bobDhPubKey
        state.DHr = bobDhPubKey
    }
    
    func bobInit() {
        
    }
    
    func encrypt() {
        
    }
    
    func decrypt() {
        
    }
    
    func trySkippedMessageKeys() {
        
    }
    
    func skipMessageKeys() {
        
    }
}
