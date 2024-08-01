//
//  headers.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import Foundation
import CryptoKit


public class HEADERS : Equatable {
    var dh: Curve25519.KeyAgreement.PublicKey
    
    var PN: UInt32 = 0
    
    var N: UInt32 = 0
    
    public init(dhPair: Curve25519.KeyAgreement.PublicKey, PN: UInt32, N: UInt32) {
        self.dh = dhPair
        self.PN = PN
        self.N = N
    }
    
    public func serialize() -> Data {
        // Convert PN to Data
        var bytesPN = Data(count: 4)
        bytesPN.withUnsafeMutableBytes {
            $0.storeBytes(of: PN.littleEndian, as: UInt32.self)
        }
        
        // Convert N to Data
        var bytesN = Data(count: 4)
        bytesN.withUnsafeMutableBytes {
            $0.storeBytes(of: N.littleEndian, as: UInt32.self)
        }
        
        // Convert public key to Data
        let pubKey = dh.rawRepresentation
        
        // Compute total length
        let len = UInt32(4 + bytesPN.count + bytesN.count + pubKey.count)
        
        // Convert length to Data
        var bytesLen = Data(count: 4)
        bytesLen.withUnsafeMutableBytes {
            $0.storeBytes(of: len.littleEndian, as: UInt32.self)
        }
        
        // Concatenate all Data components
        var result = Data()
        result.append(bytesLen)
        result.append(bytesPN)
        result.append(bytesN)
        result.append(pubKey)
        
        return result
    }

    public static func deserialize(serializedData: Data) -> HEADERS? {
        var data = serializedData
        
        // Extract length
        guard data.count >= 4 else { return nil }
        let len = data.withUnsafeBytes {
            $0.load(fromByteOffset: 0, as: UInt32.self)
        }.littleEndian
        data.removeFirst(4)
        
        // Extract PN
        guard data.count >= 4 else { return nil }
        let pn = data.withUnsafeBytes {
            $0.load(fromByteOffset: 0, as: UInt32.self)
        }.littleEndian
        data.removeFirst(4)
        
        // Extract N
        guard data.count >= 4 else { return nil }
        let n = data.withUnsafeBytes {
            $0.load(fromByteOffset: 0, as: UInt32.self)
        }.littleEndian
        data.removeFirst(4)
        
        // Extract public key
        guard data.count >= 32 else { return nil } // Curve25519 public key is 32 bytes
        let pubKeyData = data.prefix(32)
        guard let publicKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: pubKeyData) else { return nil }
        
        return HEADERS(dhPair: publicKey,
                       PN: UInt32(Int(pn)),
                       N: UInt32(Int(n)))
    }
    
    public static func == (lhs: HEADERS, rhs: HEADERS) -> Bool {
        return (lhs.PN == rhs.PN &&
                lhs.N == rhs.N &&
                lhs.dh.rawRepresentation == rhs.dh.rawRepresentation)
    }
}
