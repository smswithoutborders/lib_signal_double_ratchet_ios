//
//  CryptoHelper.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 28/07/2024.
//

import Foundation


func getCipherMACParameters(mk: Data) {
    let len = 80
    let info = "ENCRYPT"
    let salt = Data(repeating: 0, count: len)
    
    return sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: "x25591_key_exchange".data(using: .utf8)!,
        outputByteCount: 32)
}
