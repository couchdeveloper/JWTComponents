import Foundation
import CommonCrypto
import XCTest
@testable import JWTComponents

final class Base64URLCodingTests: XCTestCase {
    func testStringToBase64String() {
        XCTAssertEqual(try "".base64URLEncoded(), "")
        XCTAssertEqual(try "f".base64URLEncoded(), "Zg")
        XCTAssertEqual(try "fo".base64URLEncoded(), "Zm8")
        XCTAssertEqual(try "foo".base64URLEncoded(), "Zm9v")
        XCTAssertEqual(try "foob".base64URLEncoded(), "Zm9vYg")
        XCTAssertEqual(try "fooba".base64URLEncoded(), "Zm9vYmE")
        XCTAssertEqual(try "foobar".base64URLEncoded(), "Zm9vYmFy")
    }

    func testBase64URLSringToString() {
        XCTAssertEqual(try "".base64URLDecoded(), "")
        XCTAssertEqual(try "Zg".base64URLDecoded(), "f")
        XCTAssertEqual(try "Zm8".base64URLDecoded(), "fo")
        XCTAssertEqual(try "Zm9v".base64URLDecoded(), "foo")
        XCTAssertEqual(try "Zm9vYg".base64URLDecoded(), "foob")
        XCTAssertEqual(try "Zm9vYmE".base64URLDecoded(), "fooba")
        XCTAssertEqual(try "Zm9vYmFy".base64URLDecoded(), "foobar")
    }
}
