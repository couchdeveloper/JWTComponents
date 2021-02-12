import Foundation
import Crypto

//+--------------+-------------------------------+--------------------+
//| "alg" Param  | Digital Signature or MAC      | Implementation     |
//| Value        | Algorithm                     | Requirements       |
//+--------------+-------------------------------+--------------------+
//| HS256        | HMAC using SHA-256            | Required           |
//| HS384        | HMAC using SHA-384            | Optional           |
//| HS512        | HMAC using SHA-512            | Optional           |
//| RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
//|              | SHA-256                       |                    |
//| RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
//|              | SHA-384                       |                    |
//| RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
//|              | SHA-512                       |                    |
//| ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
//| ES384        | ECDSA using P-384 and SHA-384 | Optional           |
//| ES512        | ECDSA using P-521 and SHA-512 | Optional           |
//| PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
//|              | MGF1 with SHA-256             |                    |
//| PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
//|              | MGF1 with SHA-384             |                    |
//| PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
//|              | MGF1 with SHA-512             |                    |
//| none         | No digital signature or MAC   | Optional           |
//|              | performed                     |                    |
//+--------------+-------------------------------+--------------------+

// See also: https://tools.ietf.org/html/rfc7518#section-3.1

// Supported JWT Signing Algorithms
public enum JWTAlgorithm: String, CaseIterable {
    /// HMAC using SHA-256. For confidential clients only.
    case HS256 = "HS256"
    /// HMAC using SHA-384. For confidential clients only.
    case HS384 = "HS384"
    /// HMAC using SHA-512. For confidential clients only.
    case HS512 = "HS512"
    ///ECDSA using P-256 and SHA-256. Recommended for non-confidential clients.
    case ES256 = "ES256"
    /// ECDSA using P-384 and SHA-384. For non-confidential clients.
    case ES384 = "ES384"
    /// ECDSA using P-521 and SHA-512. For non-confidential clients.
    case ES512 = "ES512"
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
}

public enum JWTFactory {
    public static func createJWTVerifier(algorithm: JWTAlgorithm, keyData: Data) throws -> JWSVerifier {
        let verifier: JWSVerifier?
        switch algorithm {
        case .HS256:
            verifier = HS_JWTVerifier<Crypto.SHA256>(withKey: keyData)

        case .HS384:
            verifier = HS_JWTVerifier<Crypto.SHA384>(withKey: keyData)

        case .HS512:
            verifier = HS_JWTVerifier<Crypto.SHA512>(withKey: keyData)

        case .ES256:
            let publicKey = try ES256_JWTVerifier.PublicKey(rawRepresentation: keyData)
            verifier = ES256_JWTVerifier(publicKey: publicKey)

        case .ES384:
            let publicKey = try ES384_JWTVerifier.PublicKey(rawRepresentation: keyData)
            verifier = ES384_JWTVerifier(publicKey: publicKey)

        case .ES512:
            let publicKey = try ES512_JWTVerifier.PublicKey(rawRepresentation: keyData)
            verifier = ES512_JWTVerifier(publicKey: publicKey)
        }

        guard let jwtVerifier = verifier else {
            throw error("Could not create JWT Verifier")
        }
        return jwtVerifier
    }

    public static func createJWTSigner(algorithm: JWTAlgorithm, keyData: Data) throws -> JWSSigner {
        let signer: JWSSigner?
        switch algorithm {
        case .HS256:
            signer = HS_JWTSigner<Crypto.SHA256>(withKey: keyData)

        case .HS384:
            signer = HS_JWTSigner<Crypto.SHA384>(withKey: keyData)

        case .HS512:
            signer = HS_JWTSigner<Crypto.SHA512>(withKey: keyData)

        case .ES256:
            let privateKey = try ES256_JWTSigner.PrivateKey(rawRepresentation: keyData)
            signer = ES256_JWTSigner(privateKey: privateKey)

        case .ES384:
            let privateKey = try ES384_JWTSigner.PrivateKey(rawRepresentation: keyData)
            signer = ES384_JWTSigner(privateKey: privateKey)

        case .ES512:
            let privateKey = try ES512_JWTSigner.PrivateKey(rawRepresentation: keyData)
            signer = ES512_JWTSigner(privateKey: privateKey)
        }

        guard let jwtSigner = signer else {
            throw error("Could not create JWT Verifier")
        }
        return jwtSigner
    }
}

public extension JWTFactory {
     static func createJWTVerifier(algorithm string: String, keyData: Data) throws -> JWSVerifier {
        guard let algorithm = JWTAlgorithm(rawValue: string) else {
            throw error("algorithm \(string) not supported")
        }
        return try createJWTVerifier(algorithm: algorithm, keyData: keyData)
    }

    static func createJWTSigner(algorithm string: String, keyData: Data) throws -> JWSSigner {
        guard let algorithm = JWTAlgorithm(rawValue: string) else {
            throw error("algorithm \(string) not supported")
        }
        return try createJWTSigner(algorithm: algorithm, keyData: keyData)
    }
}

extension JWTFactory: ErrorThrowing {}

// MARK: - HSxxx

struct HS_JWTVerifier<H: HashFunction>: JWSVerifier {
    var algorithm: JWTAlgorithm
    let symmetricKey: SymmetricKey

    init?(withKey data: Data) {
        guard let algorithm = JWTAlgorithm(rawValue: "HS\(H.Digest.byteCount * 8)") else {
            return nil
        }
        self.algorithm = algorithm
        self.symmetricKey = SymmetricKey(data: data)
    }

    func verify(message: Data, signature: Data) throws {
        guard HMAC<H>.isValidAuthenticationCode(signature, authenticating: message, using: symmetricKey) else {
            throw error("JWT signature verification failed, using algorithm \(algorithm.rawValue)")
        }
    }
}

struct HS_JWTSigner<H: HashFunction>: JWSSigner {
    var algorithm: JWTAlgorithm
    let symmetricKey: SymmetricKey

    init?(withKey data: Data) {
        guard let algorithm = JWTAlgorithm(rawValue: "HS\(H.Digest.byteCount * 8)") else {
            return nil
        }
        self.algorithm = algorithm
        self.symmetricKey = SymmetricKey(data: data)
    }

    func sign(message: Data) throws -> Data {
        let authenticationCode = HMAC<H>.authenticationCode(for: message, using: symmetricKey)
        return Data(authenticationCode)
    }
}


// MARK: - ES256

struct ES256_JWTVerifier: JWSVerifier {
    typealias PublicKey = P256.Signing.PublicKey
    typealias Signature = P256.Signing.ECDSASignature

    var algorithm: JWTAlgorithm
    let publicKey: PublicKey

    init(publicKey: PublicKey) {
        algorithm = .ES256
        self.publicKey = publicKey
    }

    func verify(message: Data, signature: Data) throws {
        let ecdsaSignature = try Signature(rawRepresentation: signature)
        guard publicKey.isValidSignature(ecdsaSignature, for: message) else {
            throw error("JWT signature verification failed, using algorithm \(algorithm.rawValue)")
        }
    }
}

struct ES256_JWTSigner: JWSSigner {
    typealias PrivateKey = P256.Signing.PrivateKey
    typealias Signature = P256.Signing.ECDSASignature

    var algorithm: JWTAlgorithm
    let privateKey: PrivateKey

    init(privateKey: PrivateKey) {
        algorithm = .ES256
        self.privateKey = privateKey
    }

    func sign(message: Data) throws -> Data {
        let signature = try privateKey.signature(for: message)
        return signature.rawRepresentation
    }
}


// MARK: - ES384

struct ES384_JWTVerifier: JWSVerifier {
    typealias PublicKey = P384.Signing.PublicKey
    typealias Signature = P384.Signing.ECDSASignature

    var algorithm: JWTAlgorithm
    let publicKey: PublicKey

    init(publicKey: PublicKey) {
        algorithm = .ES384
        self.publicKey = publicKey
    }

    func verify(message: Data, signature: Data) throws {
        let ecdsaSignature = try Signature(rawRepresentation: signature)
        guard publicKey.isValidSignature(ecdsaSignature, for: message) else {
            throw error("JWT signature verification failed, using algorithm \(algorithm.rawValue)")
        }
    }
}

struct ES384_JWTSigner: JWSSigner {
    typealias PrivateKey = P384.Signing.PrivateKey
    typealias Signature = P384.Signing.ECDSASignature

    var algorithm: JWTAlgorithm
    let privateKey: PrivateKey

    init(privateKey: PrivateKey) {
        algorithm = .ES384
        self.privateKey = privateKey
    }

    func sign(message: Data) throws -> Data {
        let signature = try privateKey.signature(for: message)
        return signature.rawRepresentation
    }
}


// MARK: - ES512
struct ES512_JWTVerifier: JWSVerifier {
    typealias PublicKey = P521.Signing.PublicKey
    typealias Signature = P521.Signing.ECDSASignature

    var algorithm: JWTAlgorithm
    let publicKey: PublicKey

    init(publicKey: PublicKey) {
        algorithm = .ES512
        self.publicKey = publicKey
    }

    func verify(message: Data, signature: Data) throws {
        let ecdsaSignature = try Signature(rawRepresentation: signature)
        guard publicKey.isValidSignature(ecdsaSignature, for: message) else {
            throw error("JWT signature verification failed, using algorithm \(algorithm.rawValue)")
        }
    }
}

struct ES512_JWTSigner: JWSSigner {
    typealias PrivateKey = P521.Signing.PrivateKey
    typealias Signature = P521.Signing.ECDSASignature

    var algorithm: JWTAlgorithm
    let privateKey: PrivateKey

    init(privateKey: PrivateKey) {
        algorithm = .ES512
        self.privateKey = privateKey
    }

    func sign(message: Data) throws -> Data {
        let signature = try privateKey.signature(for: message)
        return signature.rawRepresentation
    }
}
