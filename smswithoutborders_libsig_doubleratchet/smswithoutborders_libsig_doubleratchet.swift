//
//  smswithoutborders_libsig_doubleratchet.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import CryptoKit

class smswithoutborders_libsig_doubleratchet {
    static func aliceInit(state: States,
                          SK: [UInt8],
                          bobDhPubKey: Curve25519.KeyAgreement.PublicKey,
                          keystoreAlias: String) throws {
        state.DHs = try Ratchet.GENERATE_DH(keystoreAlias: keystoreAlias)
        state.DHr = bobDhPubKey
        (state.RK, state.CKs) = try Ratchet.KDF_RK(rk: SK,
            dh: try Ratchet.DH(privateKey: state.DHs!, peerPublicKey: state.DHr!))
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
    
    static func encrypt(state: States, data: [UInt8], AD: [UInt8]) throws -> (header: HEADERS, cipherText: [UInt8]) {
        var mk: [UInt8]
        (state.CKs, mk) = try Ratchet.KDF_CK(ck: state.CKs!)
        let header = HEADERS(dhPair: state.DHs!.publicKey, PN: UInt32(state.PN), N: UInt32(state.Ns))
        state.Ns += 1
        return (header,
                try Ratchet.ENCRYPT(
                    mk: mk,
                    plainText: data,
                    associatedData: Ratchet.CONCAT(AD: AD, headers: header)))
    }
    
    static func decrypt(state: States, header: HEADERS, cipherText: [UInt8], AD: [UInt8], keystoreAlias: String) throws -> [UInt8] {
        let plaintext = trySkippedMessageKeys(state: state, header: header, cipherText: cipherText, AD: AD)
        if plaintext != nil {
            return plaintext!
        }

        if header.dh.rawRepresentation != state.DHr?.rawRepresentation {
            skipMessageKeys(state: state, until: Int(header.PN))
            try Ratchet.DHRatchet(state: state, header: header, keystoreAlias: keystoreAlias)
        }

        skipMessageKeys(state: state, until: Int(header.N))
        let mk: [UInt8]
        (state.CKr, mk) = try Ratchet.KDF_CK(ck: state.CKr!)
        state.Nr += 1
        return try Ratchet.DECRYPT(mk: mk, cipherText: cipherText, associatedData: Ratchet.CONCAT(AD: AD, headers: header))
    }
    
    private static func trySkippedMessageKeys(state: States, header: HEADERS, cipherText: [UInt8], AD: [UInt8]) -> [UInt8]? {
        return nil
    }
    
    private static func skipMessageKeys(state: States, until: Int) {
        
    }
}
