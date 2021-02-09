import struct Foundation.Data

public protocol JWSVerifier {
    /// Returns the algorithm the verifier is using.
    var algorithm: JWTAlgorithm { get }

    /// Verifies the JWS header and payload against the signature.
    /// - Parameters:
    ///   - message: The header and payload which is to be verfied, which is `ASCII(Base64URL(header) + "." + Base64URL(payload))`.
    ///   - signature: A sequence of contiguous bytes which represents the signature of the JWS.
    func verify(message: Data, signature: Data) throws
}

extension JWSVerifier {

    func verify(jwt: JWTComponents.JWSCompactSerialization) throws {
        let jwtComponents = try JWTComponents(jwt: jwt)
        try verify(jwtComponents: jwtComponents)
    }

    func verify(jwtComponents: JWTComponents) throws {
        guard let payload = jwtComponents.payload else {
            throw error("no payload")
        }
        guard let signatureData = jwtComponents.signatureData else {
            throw error("no signature")
        }
        let message = "\(jwtComponents.header).\(payload)"
        guard let messageData = message.data(using: .nonLossyASCII) else {
            throw error("malformed JWT")
        }
        try validateAlgorithm(jwtComponents: jwtComponents)
        try verify(message: messageData, signature: signatureData)
    }

    func validateAlgorithm(jwtComponents: JWTComponents) throws {
        let jose = try jwtComponents.header(as: JOSEHeader.self)
        guard jose.alg == self.algorithm.rawValue else {
            throw error("JOSE `alg` claim (algorithm) \"\(jose.alg ?? "")\" does not match the JWT verifiers algorithm \"\(self.algorithm.rawValue)\"")
        }
        guard jose.typ == "JWT" else {
            throw error("JOSE `typ` claim \"\(jose.typ ?? "")\" does not match required value \"JWT\"")
        }
    }

    func verifiedClaims<Claims: Decodable>(jwt: Base64URLEncodedString, claimsType: Claims.Type) throws -> Claims {
        try self.verify(jwt: jwt)
        let claims = try Self.unverifiedClaims(jwt: jwt, claimsType: claimsType)
        return claims
    }

    static func unverifiedClaims<Claims: Decodable>(jwt: Base64URLEncodedString, claimsType: Claims.Type) throws -> Claims {
        return try JWTParser.claims(jwt: jwt, claimsType: claimsType)
    }
}

extension JWSVerifier {
    func error(_ message: @autoclosure () -> String, underlyingError: Swift.Error? = nil, function: StaticString = #function, file: StaticString = #file, line: UInt = #line) -> Swift.Error {
        return Error(message(), underlyingError: underlyingError, subjectType: "\(type(of: self))", subjectDescription: String(reflecting: self), function: function, file: file, line: line)
    }
}
