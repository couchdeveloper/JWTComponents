import Foundation
import XCTest
import JWTComponents

extension JWTComponents {
    var keyIdentifier: String? {
        let kid = try? getValue(String.self, forHeaderParameter: "kid")
        return kid
    }
}

final class JWTComponentsTests: XCTestCase {

    func testListAllAlgorithms() {
        let algs = JWTAlgorithm.allCases.map { $0.rawValue }
        print("JWS supported algorithms: \(algs.joined(separator: ", "))")
    }

    func testCanParseJOSEHeader() throws {
        let jwt = Fixture.all.filter { $0.algorithm == "ES256"} .first!.jwt
        let jwtc = try JWTComponents(jwt: jwt)

        let joseHeader = try jwtc.header(as: JOSEHeader.self)
        XCTAssertEqual(joseHeader.typ,  "JWT")
        XCTAssertEqual(joseHeader.alg, "ES256")
    }

    func testCanParsePayload() throws {
        let jwt = Fixture.all.filter { $0.algorithm == "ES256"} .first!.jwt
        let jwtPayload = String(jwt.split(separator: ".").dropFirst().first!)
        let payload = try JWTComponents(jwt: jwt).payload
        XCTAssertEqual(payload, jwtPayload)
    }

    func testCanParseSignature() throws {
        let jwt = Fixture.all.filter { $0.algorithm == "ES256"} .first!.jwt
        let jwtSignature = String(jwt.split(separator: ".").last!)
        let signature = try JWTComponents(jwt: jwt).signature
        XCTAssertEqual(signature, jwtSignature)
    }

    func testReturnsJWT() throws {
        let jwt = Fixture.all.filter { $0.algorithm == "ES256"} .first!.jwt
        let actualJWT = try JWTComponents(jwt: jwt).jwt
        XCTAssertNotNil(actualJWT)
        XCTAssertEqual(actualJWT, jwt)
    }

    func testSignShouldSucceed() throws {
        var jwtc = JWTComponents()
        jwtc.setIssuer("TheIssuer")
        let key = "secret".data(using: .ascii)!
        let signer = try JWTFactory.createJWTSigner(algorithm: .HS256, keyData: key)
        XCTAssertNoThrow(try jwtc.sign(signer: signer))
    }

    func testExampleCreateJWTSuccess() throws {
        var jwtc = JWTComponents()
        jwtc.setIssuer("com.mycompany")
        jwtc.setSubject("OIDC-client")
        try jwtc.setValue("HS256", forHeaderParameter: .alg)

        let key = "secure".data(using: .utf8)!
        XCTAssertNoThrow(try jwtc.sign(withKey: key))
        XCTAssertNoThrow(try jwtc.jwtCompact())
        let verifier = try JWTFactory.createJWTVerifier(algorithm: "HS256", keyData: key)

        XCTAssertNoThrow(try jwtc.verify(with: verifier))
    }

    func testInitShouldFail() throws {
        XCTAssertThrowsError(try JWTComponents(jwt: "ghghg")) { error in
            XCTAssertTrue(String(describing: error).contains("malformed JWT"))
            XCTAssertTrue(String(reflecting: error).contains("malformed JWT"))
        }
    }

    func testExample1() throws {
        let jwt = "ewogICJhbGciOiAiRVMyNTYiLAogICJ0eXAiOiAiSldUIgp9.ewogICJzdWIiOiAiMTIzNDU2Nzg5MCIsCiAgIm5hbWUiOiAiSm9obiBEb2UiLAogICJpYXQiOiAxNTE2MjM5MDIyCn0.rrpQhPNCG5_Kf7tyzrd25D7I0GK4aYO_NPqmtM8i8NJR1FLj_dt4G7FpM5xwAaZyXuDzguhKHupoABpHYVRNxQ"

        XCTAssertNoThrow(try JWTComponents(jwt: jwt))
    }

    func testValidation() throws {
        /*
        {
          "alg": "HS256",
          "typ": "JWT"
        }
        {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022
        }
        */
        let key = "secret".data(using: .utf8)!
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"

        struct MyHeader: Decodable {
            let alg: String
            let typ: String
        }
        struct MyClaims: Decodable {
            let sub: String
            let name: String
            let iat: Int
        }
        let verifier = try JWTFactory.createJWTVerifier(algorithm: .HS256, keyData: key)
        try JWTComponents(jwt: jwt).validate(with: verifier, forHeader: MyHeader.self, claims: MyClaims.self) { (header, claims) in
            // TODO: add validations
            //print("header: \(header)")
            //print("claims: \(claims)")
        }
    }

    func test_validateFails_when_expired() throws {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        var jwtc = try JWTComponents(jwt: jwt)
        let exp = Int(Date().addingTimeInterval(-3600).timeIntervalSince1970)
        jwtc.setExpiration(exp)

        XCTAssertThrowsError(try jwtc.validate()) { error in
            XCTAssert(String(describing: error).contains("expired"))
        }
    }

    func test_validatSucceeds_when_almostEpired() throws {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        var jwtc = try JWTComponents(jwt: jwt)
        let exp = Int(Date().addingTimeInterval(0).timeIntervalSince1970)
        jwtc.setExpiration(exp)

        XCTAssertNoThrow(try jwtc.validate())
    }

    func test_valideteFails_when_NotBeforeNotMet() throws {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        var jwtc = try JWTComponents(jwt: jwt)
        let nbf = Int(Date().addingTimeInterval(3600).timeIntervalSince1970)
        jwtc.setNotBefore(nbf)

        XCTAssertThrowsError(try jwtc.validate()) { error in
            XCTAssert(String(describing: error).contains("cannot process"))
        }
    }

    func test_validateSucceeeds_when_almostNotBeforeNotMet() throws {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        var jwtc = try JWTComponents(jwt: jwt)
        let nbf = Int(Date().addingTimeInterval(0).timeIntervalSince1970)
        jwtc.setNotBefore(nbf)

        XCTAssertNoThrow(try jwtc.validate())
    }

    // TODO: add more tests
}
