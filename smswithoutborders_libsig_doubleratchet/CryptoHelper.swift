//
//  CryptoHelper.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 28/07/2024.
//

import Foundation
import CryptoKit

class CryptoHelper {
    
    static func getCipherMACParameters(mk: Data) -> Data {
        let len = 80
        let info = "ENCRYPT".data(using: .utf8)!
        let salt = Data(repeating: 0, count: len)
        
        let key = SymmetricKey(data: mk)
        
        let symKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: key,
                              salt: salt, info: info, outputByteCount: 32)
        
        return symKey.withUnsafeBytes {
            Data(Array($0))
        }
    }
}
