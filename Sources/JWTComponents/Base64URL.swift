import Foundation
import CryptoKit

public typealias Base64URLEncodedString = String
public typealias Base64URLEncodedData = Data

public extension Data {
    /// Returns a base64URL encoded data from `self`.
    func base64URLEncoded() -> Base64URLEncodedData {
        var base64data = self.base64EncodedData()

        // base64 -> base64URL
        return base64data.withUnsafeMutableBytes { (rawMutableBufferPointer) in
            let unsafeMutableBufferPointer = rawMutableBufferPointer.bindMemory(to: UInt8.self)
            let p = unsafeMutableBufferPointer.baseAddress!
            let count = unsafeMutableBufferPointer.count
            var i = 0
            var padding = 0
            while i < count {
                switch p[i] {
                case 0x2B: // "+"
                    p[i] = 0x2D // "-"
                case 0x2F: // "/"
                    p[i] = 0x5F // "_"
                case 0x3D: // "="
                    padding += 1
                default:
                    break
                }
                i += 1
            }
            let buffer = unsafeMutableBufferPointer.dropLast(padding)
            return Data(buffer)
        }
    }

    /// Returns the decoded Data from base64URL encoded `self`.
    func base64URLDecoded() throws -> Data {
        // base64URL -> base64
        var base64Data = self
        let padding = base64Data.count % 4 > 0 ? count % 4 : 0
        base64Data.append([0x3D, 0x3D, 0x3D, 0x3D], count: padding)
        base64Data.withUnsafeMutableBytes { (rawMutableBufferPointer) in
            let unsafeMutableBufferPointer = rawMutableBufferPointer.bindMemory(to: UInt8.self)
            let p = unsafeMutableBufferPointer.baseAddress!
            let count = unsafeMutableBufferPointer.count
            var i = 0
            while i < count {
                switch p[i] {
                case 0x2D: // "-"
                    p[i] = 0x2B // "_"
                case 0x5F: // "/"
                    p[i] = 0x2F // "+"
                default:
                    break
                }
                i += 1
            }
        }
        guard let data = Data(base64Encoded: base64Data) else {
            throw error("could not decode base64 data")
        }
        return data
    }

    /// Returns a base64URL encoded string from `self`.
    func base64URLEncodedString() -> Base64URLEncodedString {
        var base64data = self.base64EncodedData()

        return base64data.withUnsafeMutableBytes { (rawMutableBufferPointer) in
            let data = self.base64URLEncoded()
            return String(bytes: data, encoding: .nonLossyASCII)!
        }
    }

}

extension Data: ErrorThrowing {}

public extension StringProtocol {

    /// Returns a string from the base64URL encoded octes of the UTF-8 representation of `self`.
    func base64URLEncoded() throws -> Base64URLEncodedString {
        guard let data = self.data(using: .utf8) else {
            throw error("Could not encode string to UTF-8")
        }
        return data.base64URLEncodedString()
    }

    /// Decodes `self` from a base64URL encoded string and returns a String value interpreting the octets as a UTF-8 sequence.
    func base64URLDecoded() throws -> String {
        let data = try self.base64URLDecodedData()
        guard let string = String(data: data, encoding: .utf8) else {
            throw error("Could not create UTF-8 string from data")
        }
        return string
    }

    /// Decodes `self` from a base64URL encoded string and returns a Data value.
    func base64URLDecodedData() throws -> Data {
        guard let base64URLEncodedData = self.data(using: .nonLossyASCII) else {
            throw error("decoding error: string is not base64URL encoded")
        }
        return try base64URLEncodedData.base64URLDecoded()
    }
}

extension StringProtocol {
    func error(_ message: @autoclosure () -> String, underlyingError: Swift.Error? = nil, function: StaticString = #function, file: StaticString = #file, line: UInt = #line) -> Swift.Error {
        return Error(message(), underlyingError: underlyingError, subjectType: "\(type(of: self))", subjectDescription: String(reflecting: self), function: function, file: file, line: line)
    }
}
