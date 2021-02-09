import struct Foundation.Data

public protocol JWSSigner {
    /// Returns the algorithm the verifier is using.
    var algorithm: JWTAlgorithm { get }

    /// Signs the JWS header and payload and returns a signature.
    /// - Parameter message: The header and payload which is to be signed, which is `ASCII(Base64URL(header) + "." + Base64URL(payload))`.
    func sign(message: Data) throws -> Data
}

extension JWSSigner {

    func sign(jwtComponents: JWTComponents) throws -> JWTComponents {
        let alg = try jwtComponents.getValue(String.self, forHeaderParameter: .alg)
        guard alg == nil || alg == algorithm.rawValue else {
            throw error("Signer's algorithm \(algorithm) does not match JWT's algorithm: \(alg!) ")
        }
        var jwtC = jwtComponents
        guard let payload = jwtC.payload else {
            throw error("no payload")
        }
        try jwtC.setValue("JWT", forHeaderParameter: .typ)
        try jwtC.setValue(algorithm.rawValue, forHeaderParameter: .alg)
        let header = jwtC.header
        let message = "\(header).\(payload)"
        guard let messageData = message.data(using: .nonLossyASCII) else {
            throw error("malformed JWT")
        }
        let sig = try sign(message: messageData)
        jwtC.set(header: header, payload: payload, signature: sig)

        return jwtC
    }

}

extension JWSSigner {
    func error(_ message: @autoclosure () -> String, underlyingError: Swift.Error? = nil, function: StaticString = #function, file: StaticString = #file, line: UInt = #line) -> Swift.Error {
        return Error(message(), underlyingError: underlyingError, subjectType: "\(type(of: self))", subjectDescription: String(reflecting: self), function: function, file: file, line: line)
    }
}
