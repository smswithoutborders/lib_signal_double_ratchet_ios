// The Swift Programming Language
// https://docs.swift.org/swift-book
//
//  smswithoutborders_libsig_doubleratchet.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import CryptoKit

class Ratchet {
    enum RatchetErrors: Error {
        case maxSkipExceeded
    }
    
    static private let MAX_SKIP = 100
    static func aliceInit(state: States,
                          SK: [UInt8],
                          bobDhPubKey: Curve25519.KeyAgreement.PublicKey,
                          keystoreAlias: String?) throws {
        state.DHs = try RatchetProtocols.GENERATE_DH(keystoreAlias: keystoreAlias ?? nil)
        state.DHr = bobDhPubKey
        (state.RK, state.CKs) = try RatchetProtocols.KDF_RK(rk: SK,
            dh: try RatchetProtocols.DH(privateKey: state.DHs!, peerPublicKey: state.DHr!))
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
        (state.CKs, mk) = try RatchetProtocols.KDF_CK(ck: state.CKs!)
        let header = HEADERS(dhPair: state.DHs!.publicKey, PN: UInt32(state.PN), N: UInt32(state.Ns))
        state.Ns += 1
        return (header,
                try RatchetProtocols.ENCRYPT(
                    mk: mk,
                    plainText: data,
                    associatedData: RatchetProtocols.CONCAT(AD: AD, headers: header)))
    }
    
    static func decrypt(state: States, header: HEADERS, cipherText: [UInt8], AD: [UInt8], keystoreAlias: String?) throws -> [UInt8] {
        let plaintext = try trySkippedMessageKeys(state: state, header: header, cipherText: cipherText, AD: AD)
        if plaintext != nil {
            return plaintext!
        }

        if header.dh.rawRepresentation != state.DHr?.rawRepresentation {
            try skipMessageKeys(state: state, until: Int(header.PN))
            try RatchetProtocols.DHRatchet(state: state, header: header, keystoreAlias: keystoreAlias)
        }

        try skipMessageKeys(state: state, until: Int(header.N))
        let mk: [UInt8]
        (state.CKr, mk) = try RatchetProtocols.KDF_CK(ck: state.CKr!)
        state.Nr += 1
        return try RatchetProtocols.DECRYPT(mk: mk, cipherText: cipherText, associatedData: RatchetProtocols.CONCAT(AD: AD, headers: header))
    }
    
    private static func trySkippedMessageKeys(state: States, header: HEADERS, cipherText: [UInt8], AD: [UInt8]) throws -> [UInt8]? {
        let headerBytes = header.dh.rawRepresentation.withUnsafeBytes { data in
            return Array(data)
        }
        let key = Commons.Pair(first: headerBytes, second: Int(header.N))
        if (state.MKSKIPPED.contains { $0.key == key }) {
            let mk = state.MKSKIPPED[key]
            state.MKSKIPPED.removeValue(forKey: key)
            return try RatchetProtocols.DECRYPT(mk: mk!, cipherText: cipherText, associatedData: AD)
        }
        return nil
    }
    
    private static func skipMessageKeys(state: States, until: Int) throws {
        if state.Nr + MAX_SKIP < until {
            throw RatchetErrors.maxSkipExceeded
        }
        
        if state.CKr != nil {
            while state.Nr < until {
                let dhrBytes = state.DHr!.rawRepresentation.withUnsafeBytes { data in
                    return Array(data)
                }
                let mk: [UInt8]
                (state.CKr, mk) = try RatchetProtocols.KDF_CK(ck: state.CKr!)
                state.MKSKIPPED[Commons.Pair(first: dhrBytes, second: state.Nr)] = mk
                state.Nr += 1
            }
        }
    }
}
