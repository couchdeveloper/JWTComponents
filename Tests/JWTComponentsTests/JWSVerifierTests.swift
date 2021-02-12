import Foundation
import Crypto
import XCTest
@testable import JWTComponents

class JWSVerifierTests: XCTestCase {

    /// JWT using algorithm  `verifier.algorithm` using the secret string "secret".
    /// generated with `https://jwt.io`
    func testAlgorithmName() throws {
        let verifier = HS_JWTVerifier<SHA256>.init(withKey: "secret".data(using: .utf8)!)
        XCTAssertNotNil(verifier, "Could not create HMAC_JWTVerifier with Hash: \(SHA256.self)")
        if let verifier = verifier {
            XCTAssertEqual(verifier.algorithm.rawValue, "HS256")
        }
    }

    func testHMACJWTVerifierValidAuthenticationCode() throws {
        try testValidAuthenticationCodeWith(SHA256.self)
        try testValidAuthenticationCodeWith(SHA384.self)
        try testValidAuthenticationCodeWith(SHA512.self)
    }

    func testHMACJWTVerifierInValidSecret() throws {
        try testInvalidSecretWith(SHA256.self)
        try testInvalidSecretWith(SHA384.self)
        try testInvalidSecretWith(SHA512.self)
    }

    func test_allVerifiers() throws {
        try Fixture.all.forEach { fixture in
            let jwt = fixture.jwt
            let algorithm = JWTAlgorithm(rawValue: fixture.algorithm)!
            let keyData = fixture.verifierKeyData
            let verifier = try JWTFactory.createJWTVerifier(algorithm: algorithm, keyData: keyData)
            XCTAssertNoThrow(try verifier.verify(jwt: jwt), "Verifier: \(verifier)")
        }
    }

    // MARK: -

    func testValidAuthenticationCodeWith<H: HashFunction>(_ hashFunctionType: H.Type) throws {
        do {
            guard let verifier = HS_JWTVerifier<H>.init(withKey: "secret".data(using: .utf8)!) else {
                throw "could not create JWT verifier"
            }
            let jwt = Fixture.all.filter { $0.algorithm == verifier.algorithm.rawValue} .first!.jwt
            try verifier.verify(jwt: jwt)
        } catch {
            XCTFail("Test failure: \(error)")
        }
    }

    func testInvalidSecretWith<H: HashFunction>(_ hashFunctionType: H.Type) throws {
        do {
            guard let verifier = HS_JWTVerifier<H>.init(withKey: "invalid".data(using: .utf8)!) else {
                throw "could not create JWT verifier"
            }
            let jwt = Fixture.all.filter { $0.algorithm == verifier.algorithm.rawValue} .first!.jwt
            try verifier.verify(jwt: jwt)
            XCTFail("Unexpected PASS")
        } catch {
            print("\(error)")
        }
    }

}
