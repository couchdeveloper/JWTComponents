import Foundation
import XCTest
@testable import JWTComponents

final class JWSComponentsValidationTests: XCTestCase {

    func testValidIssuerWhereValueIsNotAnURI() throws {
        let json = """
        {
            "iss": "notAnUri"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let claims = try decoder.decode(RegisteredClaims.self, from: json)
        XCTAssertEqual(claims.issuer, "notAnUri")
    }

    func testValidIssuerWhereValueIsAnURI() throws {
        let json = """
        {
            "iss": "www.example.com"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let claims = try decoder.decode(RegisteredClaims.self, from: json)
        XCTAssertEqual(claims.issuer, "www.example.com")
    }

    func testValidIssuer() throws {
        let json = """
        {
            "iss": "A : A"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        XCTAssertThrowsError(try decoder.decode(RegisteredClaims.self, from: json)) { error in
            print("PASS with error: \(error)")
        }
    }

    func testAudienceWhereValueIsSingle() throws {
        let json = """
        {
            "aud": "value1"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let claims = try decoder.decode(RegisteredClaims.self, from: json)
        XCTAssertNotNil(claims.audience)
        XCTAssertTrue(claims.audience != nil ? claims.audience! == "value1" : false)
    }

    func testAudienceWhereValueIsMultible() throws {
        let json = """
        {
            "aud": ["value1", "value2"]
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        do {
            let claims = try decoder.decode(RegisteredClaims.self, from: json)
            XCTAssertNotNil(claims.audience)
            XCTAssertTrue(claims.audience != nil ? claims.audience! == ["value1", "value2"] : false)
        } catch {
            XCTFail("FAIL: \(error)")
        }
    }

    func testInvalidAudienceWhereValueIsSingle() throws {
        let json = """
        {
            "aud": 123
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        XCTAssertThrowsError(try decoder.decode(RegisteredClaims.self, from: json), "") { (error) in
            print("PASS with error: \(error)")
        }
    }

    func testInvalidAudienceWhereValueIsMultiple() throws {
        let json = """
        {
            "aud": ["value1", 123]
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        XCTAssertThrowsError(try decoder.decode(RegisteredClaims.self, from: json), "") { (error) in
            print("PASS with error: \(error)")
        }
    }

    func testValidateWithValidClaimsShouldNotThrow() throws {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        let jwtc = try JWTComponents(jwt: jwt)
        XCTAssertNoThrow(try jwtc.validate())
    }

    func testValidateThrowsExpiredErrorWhenExpIsExpired() throws {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        var jwtc = try JWTComponents(jwt: jwt)
        jwtc.expiration = Int(Date().timeIntervalSince1970) - 3600
        XCTAssertThrowsError(try jwtc.validate()) { error in
            XCTAssertTrue(String(describing: error).contains("JWT expired"))
        }
    }

    func testValidateThrowsNotValidYetErrorWhenNotBeforeIsInTheFuture() throws {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        var jwtc = try JWTComponents(jwt: jwt)
        jwtc.expiration = Int(Date().timeIntervalSince1970) + 2*3600
        jwtc.notBefore = Int(Date().timeIntervalSince1970) + 1*3600
        XCTAssertThrowsError(try jwtc.validate()) { error in
            print("\(error)")
            XCTAssertTrue(String(describing: error).contains("cannot process JWT before"))
        }
    }

    func testValidateWithValidClaimsShouldNotThrow2() throws {
        var jwtc = JWTComponents()
        jwtc.leeway = 60
        jwtc.issuer = "com.couchdeveloper"
        jwtc.audience = "test"
        jwtc.expiration = Int(Date().timeIntervalSince1970)
        XCTAssertNoThrow(try jwtc.validate(), "leeway: \(jwtc.leeway)")

        let keyData = "secret".data(using: .utf8)! // Don't create a key like this in your production code, use a strong key instead!
        let signer = try JWTFactory.createJWTSigner(algorithm: .HS256, keyData: keyData)
        XCTAssertNoThrow(try jwtc.sign(signer: signer))
        XCTAssertNoThrow(try jwtc.validate())

        let verifier = try JWTFactory.createJWTVerifier(algorithm: .HS256, keyData: keyData)
        try jwtc.validate(with: verifier, forHeader: JOSEHeader.self, claims: RegisteredClaims.self) { header, claims in
            XCTAssertEqual(header.alg, "HS256")
            XCTAssertEqual(header.typ, "JWT")
            XCTAssertEqual(claims.issuer, "com.couchdeveloper")
            XCTAssertEqual(claims.audience, "test")
            XCTAssertEqual(claims.audience, ["test"])
            XCTAssertNotEqual(claims.audience, [])
            XCTAssertNotEqual(claims.audience, ["t1", "t2"])
            XCTAssertEqual("test", claims.audience)
            XCTAssertEqual( ["test"], claims.audience)
        }

        try jwtc.validate(forHeader: JOSEHeader.self, claims: RegisteredClaims.self) { header, claims in
            XCTAssertEqual(header.alg, "HS256")
            XCTAssertEqual(header.typ, "JWT")
            XCTAssertEqual(claims.issuer, "com.couchdeveloper")
            XCTAssertEqual(claims.audience, "test")
            XCTAssertEqual(claims.audience, ["test"])
            XCTAssertNotEqual(claims.audience, [])
            XCTAssertNotEqual(claims.audience, ["t1", "t2"])
            XCTAssertEqual("test", claims.audience)
            XCTAssertEqual( ["test"], claims.audience)
        }
    }

    
}
