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

    @Test func testExample() async throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let headers = HEADERS(dhPair: publicKey,
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

}
