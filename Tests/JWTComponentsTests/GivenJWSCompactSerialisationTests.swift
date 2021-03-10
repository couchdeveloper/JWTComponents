import XCTest
import JWTComponents

class GivenJWSCompactSerialisationTests: XCTestCase {

    func test_init_withValidJWS_shouldReturnParts() throws {
        let jwt = Fixture.all.filter { $0.algorithm == "ES256"} .first!.jwt
        let jwtHeader = String(jwt.split(separator: ".").first!)
        let jwtPayload = String(jwt.split(separator: ".").dropFirst().first!)
        let jwtSignature = String(jwt.split(separator: ".").dropFirst(2).last!)
        let jwtc = try JWTComponents(jws: jwt)
        XCTAssertNotNil(jwtc.jwt)
        XCTAssertNotNil(jwtc.payload)
        XCTAssertNotNil(jwtc.signature)

        XCTAssertEqual(jwtc.header, jwtHeader)
        XCTAssertEqual(jwtc.payload, jwtPayload)
        XCTAssertEqual(jwtc.signature, jwtSignature)
    }

    func test_init_withValidJWS_shouldReturnClaims() throws {
        let fixtureJWT = Fixture.all.filter { $0.algorithm == "ES256"} .first!.jwt
        let fixtureJWTPayload = String(fixtureJWT.split(separator: ".").dropFirst().first!)

        let fixturePayloadData = try! fixtureJWTPayload.base64URLDecodedData()
        let fixtureClaims = try! JSONDecoder().decode(Fixture.Payload.self, from: fixturePayloadData)

        let jwtc = try JWTComponents(jws: fixtureJWT)
        let claims = try jwtc.payload(as: Fixture.Payload.self)

        XCTAssertEqual(claims, fixtureClaims)
    }

    func test_init_withValidJWS_shouldReturnHeader() throws {
        let fixtureJWT = Fixture.all.filter { $0.algorithm == "ES256"} .first!.jwt
        let fixtureJWTHeader = String(fixtureJWT.split(separator: ".").first!)

        let fixtureHeaderData = try! fixtureJWTHeader.base64URLDecodedData()
        let fixtureHeader = try! JSONDecoder().decode(Fixture.Header.self, from: fixtureHeaderData)

        let jwtc = try JWTComponents(jws: fixtureJWT)
        let header = try jwtc.header(as: Fixture.Header.self)

        XCTAssertEqual(header, fixtureHeader)
    }

    func test_verify_ValidJWS_shouldSucceed() throws {
        try Fixture.all.forEach { fixture in
            let jwtc = try JWTComponents(jws: fixture.jwt)
            guard let alg = try jwtc.getValue(String.self, forHeaderParameter: .alg) else {
                throw "could not find algorithm in JWT header"
            }
            let verifier = try JWTFactory.createJWTVerifier(algorithm: alg, keyData: fixture.verifierKeyData)

            try jwtc.verify(with: verifier)
        }
    }

    // Currently disabled because we need a way to simulate invalid keys in the fixtures.
    func test_verify_tamperedJWS_with_validKey_shouldFail() throws {
        let fixtures: [Fixture.JWTFixture] = try Fixture.all.map { fixture in
            // "forge" a tampered JWS, which is intentionally elaborated with JWTComponents ;)
            var newFixture = fixture
            var jwsc = try JWTComponents(jws: fixture.jwt)
            let signature = jwsc.signature!
            try jwsc.setValue(true, forHeaderParameter: "isAdmin")
            let header = jwsc.header
            let payload = jwsc.payload!

            newFixture.jwt = "\(header).\(payload).\(signature)"
            return newFixture
        }

        try fixtures.forEach { fixture in
            let jwtc = try JWTComponents(jws: fixture.jwt)
            guard let alg = try jwtc.getValue(String.self, forHeaderParameter: .alg) else {
                throw "could not find algorithm in JWT header"
            }
            let verifier = try JWTFactory.createJWTVerifier(algorithm: alg, keyData: fixture.verifierKeyData)

            XCTAssertThrowsError(try jwtc.verify(with: verifier)) { error in
                XCTAssert(String(describing: error).contains("signature verification failed"))
            }
        }
    }


    // Currently disabled because we need a way to simulate invalid keys in the fixtures.
    func x_test_verify_ValidJWS_with_invalidKey_shouldFail() throws {
        let invalidKey = "invalid".data(using: .utf8)!
        try Fixture.all.forEach { fixture in
            let jwtc = try JWTComponents(jws: fixture.jwt)
            guard let alg = try jwtc.getValue(String.self, forHeaderParameter: .alg) else {
                throw "could not find algorithm in JWT header"
            }
            let verifier = try JWTFactory.createJWTVerifier(algorithm: alg, keyData: invalidKey)

            XCTAssertThrowsError(try jwtc.verify(with: verifier)) { error in
                print(error)
            }
        }
    }


}
