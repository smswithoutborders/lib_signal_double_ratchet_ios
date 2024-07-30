//
//  states.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 23/07/2024.
//

import Foundation
import CryptoKit

extension Array where Element == UInt8 {
    func toBase64() -> String {
        return Data(self).base64EncodedString()
    }
    
    static func fromBase64(_ base64String: String) -> [UInt8]? {
        guard let data = Data(base64Encoded: base64String) else { return nil }
        return [UInt8](data)
    }
}

class States: Equatable {
    
    var DHs: Curve25519.KeyAgreement.PrivateKey? = nil
    var DHr: Curve25519.KeyAgreement.PrivateKey.PublicKey? = nil
    
    var RK: [UInt8]? = nil
    var CKs: [UInt8]? = nil
    var CKr: [UInt8]? = nil
    
    var Ns = 0
    var Nr = 0
    
    var PN = 0
    
    var MKSKIPPED: [([[UInt8]: Int]): [UInt8]]?
    
    func serialized() -> Data {
        let privateKey = self.DHs!.rawRepresentation.base64EncodedString()
        
        let publicKey = self.DHs!.publicKey.rawRepresentation.base64EncodedString()
        
        var data = Data()
        data.append(String(Ns).data(using: .utf8)!)
        data.append(" ".data(using: .utf8)!)
        data.append(String(Nr).data(using: .utf8)!)
        data.append(" ".data(using: .utf8)!)
        data.append(String(PN).data(using: .utf8)!)
        data.append(" ".data(using: .utf8)!)
        data.append(RK!.toBase64().data(using: .utf8)!)
        data.append(" ".data(using: .utf8)!)
        data.append(CKs!.toBase64().data(using: .utf8)!)
        data.append(" ".data(using: .utf8)!)
        data.append(CKr!.toBase64().data(using: .utf8)!)
        data.append(" ".data(using: .utf8)!)
        data.append(privateKey.data(using: .utf8)!)
        data.append(" ".data(using: .utf8)!)
        data.append(publicKey.data(using: .utf8)!)

        let encoder = JSONEncoder()
        if let encoded = try? encoder.encode(MKSKIPPED) {
            if let jsonString = String(data: encoded, encoding: .utf8) {
                data.append((jsonString.data(using: .utf8)?.base64EncodedString().data(using: .utf8))!)
            }
        }
        
        return data
    }
    
    static func deserialize(data: Data) throws -> States? {
        let state = States()
        
        guard let string = String(data: data, encoding: .utf8) else { return nil }
        let components = string.split(separator: " ")
        
        guard components.count >= 9 else { return nil }
        
        state.Ns = Int(components[0])!
        state.Nr = Int(components[1])!
        state.PN = Int(components[2])!
        
        state.RK = Array<UInt8>.fromBase64(String(components[3]))
        state.CKs = Array<UInt8>.fromBase64(String(components[4]))
        state.CKr = Array<UInt8>.fromBase64(String(components[5]))
        
        let privateKey = Array<UInt8>.fromBase64(String(components[6]))
        let publicKey = Array<UInt8>.fromBase64(String(components[7]))
        state.DHs = try Curve25519.KeyAgreement.PrivateKey.init(rawRepresentation: privateKey!)
        state.DHr = try Curve25519.KeyAgreement.PublicKey.init(rawRepresentation: publicKey!)

        if let mkSkippedData = Data(base64Encoded: String(components[8])),
           let decodedDict = try? JSONDecoder().decode([([[UInt8]: Int]): [UInt8]].self, from: mkSkippedData) {
            state.MKSKIPPED = decodedDict
        }
        
        return state
    }
    
    static func == (lhs: States, rhs: States) -> Bool {
        return lhs.Ns == rhs.Ns &&
        lhs.Nr == rhs.Nr &&
        lhs.PN == rhs.PN &&
        lhs.RK == rhs.RK &&
        lhs.CKs == rhs.CKs &&
        lhs.CKr == rhs.CKr &&
        lhs.DHs?.rawRepresentation == rhs.DHs?.rawRepresentation &&
        lhs.DHr?.rawRepresentation == rhs.DHr?.rawRepresentation
    }
}
