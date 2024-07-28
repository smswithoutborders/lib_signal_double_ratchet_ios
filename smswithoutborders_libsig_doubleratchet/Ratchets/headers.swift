//
//  headers.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import Foundation
import CryptoKit


class HEADERS {
    var dh: Curve25519.KeyAgreement.PublicKey
    
    var PN: UInt32 = 0
    
    var N: UInt32 = 0
    
    init(dhPair: Curve25519.KeyAgreement.PrivateKey, PN: UInt32, N: UInt32) {
        self.dh = dhPair.publicKey
        self.PN = PN
        self.N = N
    }
    
    func serialize() -> [UInt32] {
        return [PN, N, UInt32(self.dh.rawRepresentation)]
    }
    
    func deserialize(data: [UInt32]) throws -> HEADERS {
        let dh = data[0]
        let pn = data[1]
        let
    }
}
