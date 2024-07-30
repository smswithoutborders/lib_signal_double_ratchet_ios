//
//  smswithoutborders_libsig_doubleratchet_Test.swift
//  smswithoutborders_libsig_doubleratchet_Test
//
//  Created by sh3rlock on 29/07/2024.
//

import Testing
import XCTest

@testable import smswithoutborders_libsig_doubleratchet
import CryptoKit

struct smswithoutborders_libsig_doubleratchet_Test {
    
    var privateKey = Curve25519.KeyAgreement.PrivateKey()
    

    @Test func testHeaders() async throws {
        
        let headers = HEADERS(dhPair: privateKey.publicKey,
                      PN: 0,
                      N: 0)
        let serialized = headers.serialize()
        serialized.withUnsafeBytes { data in
            print(Array(data))
        }

        let headers1 = HEADERS.deserialize(serializedData: serialized)!
        let serialized1 = headers1.serialize()
        serialized1.withUnsafeBytes { data in
            print(Array(data))
        }

        XCTAssertEqual(serialized, serialized1)
        XCTAssertEqual(headers, headers1)
    }
    
    @Test func testStates() async throws {
        let d = "Hello world".data(using: .utf8)?.withUnsafeBytes { data in
            return Array(data)
        }

        let d1 = "Hello world 1".data(using: .utf8)?.withUnsafeBytes { data in
            return Array(data)
        }
        
        let rprikey = privateKey.rawRepresentation.withUnsafeBytes { data in
            return Array(data)
        }
        
        let rpubkey = privateKey.publicKey.rawRepresentation.withUnsafeBytes { data in
            return Array(data)
        }

        let states = States()
        states.DHs = privateKey
        states.DHr = privateKey.publicKey
        
        states.RK = "RK".data(using: .utf8)?.withUnsafeBytes { data in
            return Array(data)
        }
        states.CKs = "CKs".data(using: .utf8)?.withUnsafeBytes { data in
            return Array(data)
        }
        states.CKr = "CKr".data(using: .utf8)?.withUnsafeBytes { data in
            return Array(data)
        }
        states.MKSKIPPED = [([rprikey:0]):d!, ([rpubkey:1]): d!]
        
        let sStates = states.serialized()
        let states1 = try States.deserialize(data: sStates)
        
        XCTAssertEqual(states, states1)
    }

}
