
//
//  smswithoutborders_libsig_doubleratchet_Test.swift
//  smswithoutborders_libsig_doubleratchet_Test
//
//  Created by sh3rlock on 29/07/2024.
//

import Testing
import CryptoKit
import XCTest

@testable import libsig_doubleratchet_smswithoutborders

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
        states.MKSKIPPED = [Commons.Pair(first: rprikey, second: 0):d!, Commons.Pair(first:rpubkey, second: 1): d!]
        
        let sStates = states.serialized()
        let states1 = try States.deserialize(data: sStates)
        
        XCTAssertEqual(states, states1)
    }
    
    @Test func testRatchets() async throws {
        // Derive shared key
        let alicePrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let alicePublicKey = alicePrivateKey.publicKey
        
        let bobPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let bobPublicKey = bobPrivateKey.publicKey
        
        let aliceSharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
        let bobSharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
        
        XCTAssertEqual(aliceSharedSecret, bobSharedSecret)
        
        let SK = aliceSharedSecret.withUnsafeBytes { data in
            return Array(data)
        }
        
        let aliceState = States()
        
        try Ratchet.aliceInit(
            state: aliceState,
            SK: SK,
            bobDhPubKey: bobPublicKey,
            keystoreAlias: nil)
        
        let bobState = States()
        Ratchet.bobInit(
            state: bobState,
            SK: SK,
            bobKeyPair: bobPrivateKey)
        
        let originalText = "Hello World".data(using: .utf8)?.withUnsafeBytes { data in
            return Array(data)
        }
        
        var (header, aliceCipherText) = try Ratchet.encrypt(
            state: aliceState,
            data: originalText!,
            AD: bobPublicKey.rawRepresentation.withUnsafeBytes {data in return Array(data)})
        
        let plainText = try Ratchet.decrypt(
            state: bobState,
            header: header,
            cipherText: aliceCipherText,
            AD: bobPublicKey.rawRepresentation.withUnsafeBytes {data in return Array(data)},
            keystoreAlias: nil)
        
        XCTAssertEqual(originalText, plainText)
        
        // Skipped messages
        for i in 0..<10 {
            print("Iterating: \(i)")
            (header, aliceCipherText) = try Ratchet.encrypt(
                state: aliceState,
                data: originalText!,
                AD: bobPublicKey.rawRepresentation.withUnsafeBytes { data in return Array(data) })
        }
        
        let skippedPlainText = try Ratchet.decrypt(
            state: bobState,
            header: header,
            cipherText: aliceCipherText,
            AD: bobPublicKey.rawRepresentation.withUnsafeBytes { data in return Array(data)},
            keystoreAlias: nil)
        
        XCTAssertEqual(originalText, skippedPlainText)
        
        var (header1, bobCipherText) = try Ratchet.encrypt(
            state: bobState,
            data: originalText!,
            AD: alicePublicKey.rawRepresentation.withUnsafeBytes { data in return Array(data)})
        
        let plainText1 = try Ratchet.decrypt(
            state: aliceState,
            header: header1,
            cipherText: bobCipherText,
            AD: alicePublicKey.rawRepresentation.withUnsafeBytes { data in return Array(data)},
            keystoreAlias: nil)
        
        XCTAssertEqual(originalText, plainText1)
    }

}
