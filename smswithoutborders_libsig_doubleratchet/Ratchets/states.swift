//
//  states.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import Foundation
import CryptoKit

class States {
    var DHs: Curve25519.KeyAgreement.PrivateKey? = nil
    var DHr: Curve25519.KeyAgreement.PrivateKey.PublicKey? = nil

    var RK: [UInt8]? = nil
    var CKs: [UInt8]? = nil
    var CKr: [UInt8]? = nil

    var Ns = 0
    var Nr = 0

    var PN = 0

    var MKSKIPPED: [[UInt8]: Int]?
    
    func serialized() -> Data {
        let privateKey = self.DHs!.rawRepresentation
        let publicKey = self.DHs!.publicKey.rawRepresentation
        
        var lenRk = RK!.count
        var lenCks = CKs!.count
        var lenCkr = CKr!.count
        
        var data = Data()
        data.append(Data(bytes: &lenRk,
                         count: MemoryLayout.size(ofValue: lenRk)))
        data.append(Data(bytes: &lenCks,
                         count: MemoryLayout.size(ofValue: lenCks)))
        data.append(Data(bytes: &lenCkr,
                         count: MemoryLayout.size(ofValue: lenCkr)))
        
        data.append(Data(bytes: &Ns,
                         count: MemoryLayout.size(ofValue: Ns)))
        data.append(Data(bytes: &Nr,
                         count: MemoryLayout.size(ofValue: Nr)))
        data.append(Data(bytes: &PN,
                         count: MemoryLayout.size(ofValue: PN)))

        return data
    }
    
    static func deserialize(data: Data) -> States {
        let int1 = data[0]
        let int2 = data[1]
        let int3 = data[2]
        let int4 = data[3]
            
        return (int1, int2, int3, int4)
    }
}
