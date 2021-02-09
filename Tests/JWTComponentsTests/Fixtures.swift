import Foundation
import CryptoKit
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

    // MARK: - ES256
    static let privateKeyPem_P256 = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglVOBHVEhQnb0EodR
    IJ82K/K3FKPMtg8ifhlwHmgo3VqhRANCAASiwkvjl72lCjlGzuP0pxumYJvid468
    4xcN47P/P6KeIB1wnh4EkNeHRzSMIkGu1XSmKi3DrxnTzx13UZ9bapEC
    -----END PRIVATE KEY-----
    """

    static let privateKeyData_P256 = try! P256.Signing.PrivateKey(pemRepresentation: privateKeyPem_P256).rawRepresentation

    static let publicKeyPem_P256 = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEosJL45e9pQo5Rs7j9KcbpmCb4neO
    vOMXDeOz/z+iniAdcJ4eBJDXh0c0jCJBrtV0piotw68Z088dd1GfW2qRAg==
    -----END PUBLIC KEY-----
    """

    static let publicKeyData_P256 = try! P256.Signing.PublicKey(pemRepresentation: publicKeyPem_P256).rawRepresentation


    // MARK: - ES384
    static let privateKeyPem_P384 = """
    -----BEGIN PRIVATE KEY-----
    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDT2hGg8pg72F0S6v7j
    HRCyP0QBpj/XJG+q7KsIKBP0AdyrRW+R4nfZ78OXEmI5GwChZANiAASY7R6H1D3A
    rJXtegyDWwbvrW3eBBykEbPYf1vj+J9GC0IzWje/J4P328bCI4cXbjt0jKVXRHcJ
    rdEcpyuXsPQUWpAlqul9J04IiWml3ebc2VH2hA8bUqkMGVWIVeEMmw8=
    -----END PRIVATE KEY-----
    """

    static let privateKeyData_P384 = try! P384.Signing.PrivateKey(pemRepresentation: privateKeyPem_P384).rawRepresentation

    static let publicKeyPem_P384 = """
    -----BEGIN PUBLIC KEY-----
    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmO0eh9Q9wKyV7XoMg1sG761t3gQcpBGz
    2H9b4/ifRgtCM1o3vyeD99vGwiOHF247dIylV0R3Ca3RHKcrl7D0FFqQJarpfSdO
    CIlppd3m3NlR9oQPG1KpDBlViFXhDJsP
    -----END PUBLIC KEY-----
    """

    static let publicKeyData_P384 = try! P384.Signing.PublicKey(pemRepresentation: publicKeyPem_P384).rawRepresentation


    // MARK: - ES512
    static let privateKeyPem_P521 = """
    -----BEGIN PRIVATE KEY-----
    MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAS92rE26cZxkUNVll
    EW4yj8QgoQOTHkEmaff+gCTLHsukmSvfR/2yCSirWTHPjGNAVpOEp0DruqwugZIB
    uup4zvOhgYkDgYYABAGuS9349o1gFe5P80OSk3Z9m9OTF9K0ZO0Eq9ZM/dzD3nZH
    kjW8Cd/LGnKcBrCIO1k0ulsbE8S9PEbOTMGADFyw8gAaN509yNsmaPxlhf6fYlOT
    oFVKVDxKs2uQycxft9+DQdTBTE1hmvOXxOPnOBZS0JQCBT16MdPvcPsaAdSmq0Wg
    Nw==
    -----END PRIVATE KEY-----
    """

    static let privateKeyData_P521 = try! P521.Signing.PrivateKey(pemRepresentation: privateKeyPem_P521).rawRepresentation

    static let publicKeyPem_P521 = """
    -----BEGIN PUBLIC KEY-----
    MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBrkvd+PaNYBXuT/NDkpN2fZvTkxfS
    tGTtBKvWTP3cw952R5I1vAnfyxpynAawiDtZNLpbGxPEvTxGzkzBgAxcsPIAGjed
    PcjbJmj8ZYX+n2JTk6BVSlQ8SrNrkMnMX7ffg0HUwUxNYZrzl8Tj5zgWUtCUAgU9
    ejHT73D7GgHUpqtFoDc=
    -----END PUBLIC KEY-----
    """

    static let publicKeyData_P521 = try! P521.Signing.PublicKey(pemRepresentation: publicKeyPem_P521).rawRepresentation

    // MARK: -

    static let jwtHeaderJson_ES256 = """
    {
      "alg": "ES256",
      "typ": "JWT"
    }
    """.compacted()

    static let jwtHeaderJson_ES384 = """
    {
      "alg": "ES384",
      "typ": "JWT"
    }
    """.compacted()

    static let jwtHeaderJson_ES512 = """
    {
      "alg": "ES512",
      "typ": "JWT"
    }
    """.compacted()


    static let jwtHeaderJson_HS256 = """
    {
      "alg": "HS256",
      "typ": "JWT"
    }
    """.compacted()

    static let jwtHeaderJson_HS384 = """
    {
      "alg": "HS384",
      "typ": "JWT"
    }
    """.compacted()

    static let jwtHeaderJson_HS512 = """
    {
      "alg": "HS512",
      "typ": "JWT"
    }
    """.compacted()

    static let jwtPayloadJson = """
    {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022
    }
    """.compacted()

    static let jwtHeaderBase64URL_HS256 = try! jwtHeaderJson_HS256.base64URLEncoded()
    static let jwtHeaderBase64URL_HS384 = try! jwtHeaderJson_HS384.base64URLEncoded()
    static let jwtHeaderBase64URL_HS512 = try! jwtHeaderJson_HS512.base64URLEncoded()
    static let jwtHeaderBase64URL_ES256 = try! jwtHeaderJson_ES256.base64URLEncoded()
    static let jwtHeaderBase64URL_ES384 = try! jwtHeaderJson_ES384.base64URLEncoded()
    static let jwtHeaderBase64URL_ES512 = try! jwtHeaderJson_ES512.base64URLEncoded()

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
              jwt: "\(jwtHeaderBase64URL_HS256).\(jwtPayloadBase64URL).ub7srKZNrlkC9jpqvPSYMwZp8IZQN1ZBCuld49qCqOs"),

        .init(verifierKeyData: symmetricKeyData,
              algorithm: "HS384",
              jwt: "\(jwtHeaderBase64URL_HS384).\(jwtPayloadBase64URL).EDqH7yZECcV2iD3BuRwjJjUreEul1_YhDP9jUqxZPru_ymdK3qt8VqrOxO9jYpJW"),

        .init(verifierKeyData: symmetricKeyData,
              algorithm: "HS512",
              jwt: "\(jwtHeaderBase64URL_HS512).\(jwtPayloadBase64URL).tKAtqOZxgyrxjs0GNb1rXpvCPda0exOFZXn3hDl22TkUreqeF0oT5bcwU6cDiztMDthAXZeBByAHNrofXRINIQ"),

        .init(verifierKeyData: publicKeyData_P256,
              signerKeyData: try! P256.Signing.PrivateKey(pemRepresentation: privateKeyPem_P256).rawRepresentation,
              algorithm: "ES256",
              jwt: "\(jwtHeaderBase64URL_ES256).\(jwtPayloadBase64URL).80V6HqQYeUPxiumEEwpFlHXC8FcyqFV0VUnMivJKb-fE7zP8GMhI-FscJWz7kqUPCjisc7N9CEWepZ4R6hzopw"),

        .init(verifierKeyData: publicKeyData_P384,
              signerKeyData: try! P384.Signing.PrivateKey(pemRepresentation: privateKeyPem_P384).rawRepresentation,
              algorithm: "ES384",
              jwt: "\(jwtHeaderBase64URL_ES384).\(jwtPayloadBase64URL).2JiM0Y6njKQ8dTSXZuFabMbQCJT_werqjSKBpS2FsqlFZNNQ1nPBlAL0csHaP0gfHn413n94o8gUCsC6g86x3NB2iZKI1mQG7blIzZA5mL4o8CkHJRXl3ibDlrcgkPv0"),

        .init(verifierKeyData: publicKeyData_P521,
              signerKeyData: try! P521.Signing.PrivateKey(pemRepresentation: privateKeyPem_P521).rawRepresentation,
              algorithm: "ES512",
              jwt: "\(jwtHeaderBase64URL_ES512).\(jwtPayloadBase64URL).AQ2AxQll3zRv7ccheGtkLGNMyxnO-9400CGgFylfXggXzrz8LUtcv3UagvlfiPoCBK3ntmJySAn2wKdzeSZj06NVAFQsi9uXuzl1rL6bSyFVSn4se_AHok7malwfGoT3G2n0sJjKP8KsTqVq45eBdBnbvVhywvH-D_x86WGomqb7i0ll")
    ]

}

class GenerateFixture: XCTestCase {

    func x_test_generateKeys() {
        let privateKey_P256 = P256.Signing.PrivateKey()
        print("=== P256:\n\(privateKey_P256.pemRepresentation)\n\n\(privateKey_P256.publicKey.pemRepresentation)")

        let privateKey_P384 = P384.Signing.PrivateKey()
        print("\n=== P384:\n\(privateKey_P384.pemRepresentation)\n\n\(privateKey_P384.publicKey.pemRepresentation)")

        let privateKey_P521 = P521.Signing.PrivateKey()
        print("\n=== P521:\n\(privateKey_P521.pemRepresentation)\n\n\(privateKey_P521.publicKey.pemRepresentation)")
    }

    func test_generateSignatures() throws {
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
