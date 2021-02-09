import XCTest
import JWTComponents

class DefaultConstructedJWTComponentsTests: XCTestCase {

    func test_jwt_shouldReturn_nil() throws {
        XCTAssertNil(JWTComponents().jwt)
    }

    func test_jwtCompact_shouldThrowError_not_signed() throws {
        XCTAssertThrowsError(try JWTComponents().jwtCompact()) { error in
            XCTAssertTrue(String(describing: error).contains("not signed"))
        }
    }

    func test_header_shouldReturn_base64URLEmptyJSONObject() throws {
        XCTAssertEqual(try JWTComponents().header.base64URLDecoded(), "{}")
    }

    func test_payload_shouldReturn_nil() throws {
        XCTAssertNil(JWTComponents().payload)
    }

    func test_signature_shouldReturnNil() throws {
        XCTAssertNil(JWTComponents().signature)
    }

    func test_sign_shouldThrowError_no_payload() throws {
        var jwtc = JWTComponents()
        let key = "secret".data(using: .ascii)!
        let signer = try JWTFactory.createJWTSigner(algorithm: .HS256, keyData: key)
        XCTAssertThrowsError(try jwtc.sign(signer: signer)) { error in
            XCTAssertTrue(String(describing: error).contains("no payload"))
            XCTAssertTrue(String(reflecting: error).contains("no payload"))
        }
    }

    func test_verify_shouldThrowError_not_signed() throws {
        let jwtc = JWTComponents()
        let key = "secret".data(using: .ascii)!
        let verifier = try JWTFactory.createJWTVerifier(algorithm: .HS256, keyData: key)
        XCTAssertThrowsError(try jwtc.verify(with: verifier)) { error in
            XCTAssertTrue(String(describing: error).contains("not signed"), "Error: \(error)")
            XCTAssertTrue(String(reflecting: error).contains("not signed"), "Error: \(error)")
        }
    }

}
