//
//  CryptoHelper.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 28/07/2024.
//

import Foundation
import CryptoKit
import CryptoSwift

public class CryptoHelper {
    
    enum CryptoHelperError : Error {
        case invalidMac
    }
    
    static func getCipherMACParameters(mk: [UInt8]) throws ->
    (key: [UInt8], authenticationKey: [UInt8], salt: [UInt8]){
        let len = 80
        let info = [UInt8]("ENCRYPT".data(using: .utf8)!)
        let salt = [UInt8](Data(repeating: 0, count: len))
        
        let hkdfOutput = try HKDF(password: mk,
             salt: salt,
             info: info, keyLength: len, variant: .sha2(.sha512))
        .calculate()
        
        let key = Array(hkdfOutput[0..<32])
        let authenticationKey = Array(hkdfOutput[32..<64])
        let iv = Array(hkdfOutput[64..<(64+16)])
        
        return (key, authenticationKey, iv)
    }
    
    static func buildVerificationHash(
        authKey: [UInt8],
        associatedData: [UInt8],
        cipherText: [UInt8]) throws -> [UInt8] {
            
            let combinedData = associatedData + cipherText
            
            return try HMAC(key: authKey, variant: .sha2(.sha256)).authenticate(combinedData)
        }
    
    static func verifyCipherText(
        mk: [UInt8], _mac: [UInt8], associatedData: [UInt8]) throws -> [UInt8] {
            let (key, authKey, iv) = try getCipherMACParameters(mk: mk)
            
            let cipherText: [UInt8] = Array(_mac[0..<(_mac.count - SHA256.byteCount)])
            
            let mac: [UInt8] = Array(_mac[(_mac.count - SHA256.byteCount)..<_mac.count])
            
            let hmac = try buildVerificationHash(
                authKey: authKey,
                associatedData: associatedData,
                cipherText: cipherText)
            
            if hmac != mac {
                throw CryptoHelperError.invalidMac
            }
            
            return cipherText
    }
}
