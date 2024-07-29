//
//  CryptoHelper.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 28/07/2024.
//

import Foundation
import CryptoKit
import CryptoSwift

class CryptoHelper {
    
    static func getCipherMACParameters(mk: Data) throws -> [UInt8] {
        let len = 80
        let info = [UInt8]("ENCRYPT".data(using: .utf8)!)
        let salt = [UInt8](Data(repeating: 0, count: len))
        
        let key = [UInt8](mk)
        
        return try HKDF(password: key,
             salt: salt,
             info: info,
             keyLength: len)
        .calculate()
    }
    
    static func buildVerificationHash(
        authKey: [UInt8],
        associatedData: [UInt8],
        cipherText: [UInt8]) throws -> [UInt8] {
            
            let combinedData = associatedData + cipherText
            
            return try HMAC(key: authKey, variant: .sha2(.sha256)).authenticate(combinedData)
        }
}
