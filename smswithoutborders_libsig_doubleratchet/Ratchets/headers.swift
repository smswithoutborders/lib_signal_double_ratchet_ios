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
    
    var PN: Int = 0
    
    var N: Int = 0
    
    init(dhPair: Curve25519.KeyAgreement.PrivateKey, PN: Int, N: Int) {
        self.dh = dhPair.publicKey
        self.PN = PN
        self.N = N
    }
    
    func serialize() -> UInt32 {
        
    }
    
    func deserialize() -> UInt32 {
        
    }
}
