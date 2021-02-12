import Foundation
import Crypto
import XCTest
@testable import JWTComponents

enum Fixture {
    typealias JSON = String

    struct Header: Codable, Equatable {
        let alg: String
        let typ: String
    }

    struct Payload: Codable, Equatable {
        let sub: String
        let name: String
        let iat: Int
    }

    enum HS256 {
        static let jwtHeaderJson = """
        {
          "alg": "HS256",
          "typ": "JWT"
        }
        """.compacted()

        static let jwtHeaderBase64URL = try! jwtHeaderJson.base64URLEncoded()
    }

    enum HS384 {
        static let jwtHeaderJson = """
        {
          "alg": "HS384",
          "typ": "JWT"
        }
        """.compacted()

        static let jwtHeaderBase64URL = try! jwtHeaderJson.base64URLEncoded()
    }

    enum HS512 {
        static let jwtHeaderJson = """
        {
          "alg": "HS512",
          "typ": "JWT"
        }
        """.compacted()

        static let jwtHeaderBase64URL = try! jwtHeaderJson.base64URLEncoded()
    }

    enum ES256 {
        static let privateKeyBase64URL = "32rctLWRYx2FLuN0xz-A6rN_VgZtJALouDdXM4CVz4U"
        static let privateKeyData = try! P256.Signing.PrivateKey(rawRepresentation: try! privateKeyBase64URL.base64URLDecodedData()).rawRepresentation

        static let publicKeyBase64URL = "36ROw0movpzkgIGjXs7u9ZDBkNuE4Zi8sPVY6LvgrU4uYH9aAK0ff4e-C6aF8pYW-FMjKYVse59RZYj1KfOzOg"
        static let publicKeyData = try! P256.Signing.PublicKey(rawRepresentation: try! publicKeyBase64URL.base64URLDecodedData()).rawRepresentation

        static let jwtHeaderJson = """
        {
          "alg": "ES256",
          "typ": "JWT"
        }
        """.compacted()

        static let jwtHeaderBase64URL = try! jwtHeaderJson.base64URLEncoded()
    }

    enum ES384 {
        static let privateKeyBase64URL = "jewo2kVDXVnbMmU4iuCJsK9YPjoxNwoZLtTdR16kQnxk_NzyjdieIuPuerj5_u6O"
        static let privateKeyData = try! P384.Signing.PrivateKey(rawRepresentation: try! privateKeyBase64URL.base64URLDecodedData()).rawRepresentation

        static let publicKeyBase64URL = "ui90_chUt5ARf6McIO7uRyhkVET9DSN3niIil7e2niHTxuy02uBbmRuG8CuAoH9CN_xnZi-5x4qkzZkNQPdoy-ZAbcz1UtZFTY9ZXrTAU5q1GKQ722wiGqqHEbyQGYQc"
        static let publicKeyData = try! P384.Signing.PublicKey(rawRepresentation: try! publicKeyBase64URL.base64URLDecodedData()).rawRepresentation

        static let jwtHeaderJson = """
        {
          "alg": "ES384",
          "typ": "JWT"
        }
        """.compacted()

        static let jwtHeaderBase64URL = try! jwtHeaderJson.base64URLEncoded()
    }

    enum ES512 {
        static let privateKeyBase64URL = "AWxkfU2FpG_yubZV-ZsLQxO8qi43Ibd4pYh-ZoBQTcjuPaEP6gzltkvfqIe2zX_8uGzdwfMDiAkKZVOKHjpOJNzr"
        static let privateKeyData = try! P521.Signing.PrivateKey(rawRepresentation: try! privateKeyBase64URL.base64URLDecodedData()).rawRepresentation

        static let publicKeyBase64URL = "AeF7exkY3iOPJMM_lITOk6LcJgb37LOO7JciZ0uhhmrEbhRgeJ2mPQKLJepcSLz7jJ8M_nNXnzSsy2bDS88wTMnEALQcSJ8rc5z64wJt-5pbZvsWxWd0kOAyzd8ehQ7Lz9rqeWIkz6JV6YquGevgz02Rd1ZV1BNhD8BjogESrRPxf-Av"
        static let publicKeyData = try! P521.Signing.PublicKey(rawRepresentation: try! publicKeyBase64URL.base64URLDecodedData()).rawRepresentation

        static let jwtHeaderJson = """
        {
          "alg": "ES512",
          "typ": "JWT"
        }
        """.compacted()

        static let jwtHeaderBase64URL = try! jwtHeaderJson.base64URLEncoded()
    }

    // MARK: -

    static let jwtPayloadJson = """
    {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022
    }
    """.compacted()

    static let jwtPayloadBase64URL = try! jwtPayloadJson.base64URLEncoded()

    static let symmetricKeyData = "secret".data(using: .utf8)!

    struct JWTFixture {
        var verifierKeyData: Data
        var signerKeyData: Data? = nil
        var algorithm: String
        var jwt: String
    }

    static let all: [JWTFixture] = [
        .init(verifierKeyData: symmetricKeyData,
              algorithm: "HS256",
              jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.ub7srKZNrlkC9jpqvPSYMwZp8IZQN1ZBCuld49qCqOs"),

        .init(verifierKeyData: symmetricKeyData,
              algorithm: "HS384",
              jwt: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.EDqH7yZECcV2iD3BuRwjJjUreEul1_YhDP9jUqxZPru_ymdK3qt8VqrOxO9jYpJW"),

        .init(verifierKeyData: symmetricKeyData,
              algorithm: "HS512",
              jwt: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.tKAtqOZxgyrxjs0GNb1rXpvCPda0exOFZXn3hDl22TkUreqeF0oT5bcwU6cDiztMDthAXZeBByAHNrofXRINIQ"),

        .init(verifierKeyData: ES256.publicKeyData,
              signerKeyData: ES256.privateKeyData,
              algorithm: "ES256",
              jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.xuSea_tH7pGFdx7E5d-GYL2O7aN2_252FVMZUhfWIVZCAxCSreO-UisNmmsuVcmY3yb51YpfysWBkOF-hgad5A"),

        .init(verifierKeyData: ES384.publicKeyData,
              signerKeyData: ES384.privateKeyData,
              algorithm: "ES384",
              jwt: "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.D9JmXkV_YCsMdrWJ86IXh-zWl8H6DPRydCJsNWVK0Ied6tNEwc-9KyYaCstzyYMsnAa-33upJ3YEG2O0YFjRRVxCgk669MG6qQVFu4bQYEYwqNOu-RhaUFHLi_JfsYJE"),

        .init(verifierKeyData: ES512.publicKeyData,
              signerKeyData: ES512.privateKeyData,
              algorithm: "ES512",
              jwt: "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.AUNSejnqROw41lpVkGT6XkowklQlCDqOSR08Txjw_kku6hVCJ2e427B2W9xHNoLAY7rxvSQU4XH11wFIK2cyYjnYANtZekZ4abqFF6ImzEhIUiP243rRsLy0ASTisaAxTIpdWQSMVWoUdmghI4-JUY0fioJUG8qaG7RoSRVlkKyxBBtC")
    ]

}

class GenerateFixture: XCTestCase {

    func x_test_generateKeys() {
        let privateKey_P256 = P256.Signing.PrivateKey()
        print("== P256:")
        print("Private: \(privateKey_P256.rawRepresentation.base64URLEncodedString())")
        print("\nPublic: \(privateKey_P256.publicKey.rawRepresentation.base64URLEncodedString())")

        let privateKey_P384 = P384.Signing.PrivateKey()
        print("== P384:")
        print("Private: \(privateKey_P384.rawRepresentation.base64URLEncodedString())")
        print("\nPublic: \(privateKey_P384.publicKey.rawRepresentation.base64URLEncodedString())")

        let privateKey_P521 = P521.Signing.PrivateKey()
        print("== P521:")
        print("Private: \(privateKey_P521.rawRepresentation.base64URLEncodedString())")
        print("\nPublic: \(privateKey_P521.publicKey.rawRepresentation.base64URLEncodedString())")
    }

    func x_test_generateSignatures() throws {
        try Fixture.all.forEach { fixture in
            let parts = fixture.jwt.split(separator: ".")
            let header = parts.first!
            let payload = parts.dropFirst(1).first!
            let messageData = "\(header).\(payload)".data(using: .nonLossyASCII)!
            let algorithm = JWTAlgorithm(rawValue: fixture.algorithm)!

            let signerKeyData = fixture.signerKeyData ?? fixture.verifierKeyData
            let signer = try JWTFactory.createJWTSigner(algorithm: algorithm, keyData: signerKeyData)
            let signature = try signer.sign(message: messageData).base64URLEncodedString()

            print("=== Generating signature for \(algorithm.rawValue):")
            print("\(try header.base64URLDecoded())\n\(try payload.base64URLDecoded()):")
            print("JWT:\n\(header).\(payload).\(signature)")
        }
    }
}

extension Fixture.JSON {
    func compacted() -> String {
        let any = try! JSONSerialization.jsonObject(with: self.data(using: .utf8)!)
        let json = try! JSONSerialization.data(withJSONObject: any, options: .sortedKeys)
        return String(data: json, encoding: .utf8)!
    }
}
