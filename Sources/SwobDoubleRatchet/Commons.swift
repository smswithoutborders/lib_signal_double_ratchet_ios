//
//  commons.swift
//  smswithoutborders_libsig_doubleratchet
//
//  Created by sh3rlock on 31/07/2024.
//

import Foundation


public class Commons {
    
    class Pair : Hashable, Equatable, Encodable, Decodable {
        init(first: [UInt8], second: Int) {
            self.first = first
            self.second = second
        }
        
        static func == (lhs: Commons.Pair, rhs: Commons.Pair) -> Bool {
            return lhs.first == rhs.first && lhs.second == rhs.second
        }
        
        func hash(into hasher: inout Hasher) {
            let fBytes = first.withUnsafeBytes { data in
                return Array(data)
            }
            let sBytes = first.withUnsafeBytes { data in
                return Array(data)
            }
            hasher.combine(fBytes + sBytes)
        }
        
        
        let first: [UInt8]
        let second: Int
    }
}
