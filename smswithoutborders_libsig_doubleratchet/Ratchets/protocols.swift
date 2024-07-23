//
//  protocols.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import Foundation


class States {
    var DHs: SecurityCurve25519? = nil
    var DHr: UInt32? = nil

    var RK: UInt32? = nil
    var CKs: UInt32? = nil
    var CKr: UInt32? = nil

    var Ns = 0
    var Nr = 0

    var PN = 0

    var MKSKIPPED = {}
    
    func serialize() throws -> UInt32 {
    }
    
    static func deserialize(data: UInt32) throws -> States {
    }
        
}


class HEADERS {
    
}

class DHRatchet {
    init() {
        
    }
    
    
    static func GENERATE_DH() {
        
    }
    
    static func DH() {
        
    }
    
    
    static func KDF_RK() {
        
    }
    
    
    static func KDF_CK() {
        
    }
    
    
    static func ENCRYPT() {
        
    }
    
    
    static func DECRYPT() {
        
    }
    
    
    static func CONCAT() {
        
    }
}
