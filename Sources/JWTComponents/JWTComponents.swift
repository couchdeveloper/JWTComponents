import struct Foundation.Data
import struct Foundation.Date
import struct Foundation.URL

/// A JSON numeric value representing the number of seconds from1970-01-01T00:00:00Z UTC until the specified
///  UTC date/time, ignoring leap seconds.
public typealias NumericDate = Int

/// A JSON string value, with the additional requirement that while arbitrary string values MAY be used, any
/// value containing a ":" character MUST be a URI [RFC3986].
public typealias StringOrURI = JWTComponents.StringOrURIValue
public typealias Audience = JWTComponents.MultiValue<StringOrURI>

public struct JOSEHeader: Codable {

    enum CodingKeys: String, CodingKey {
        case alg
        case jku
        case jwk
        case kid
        case x5u
        case x5t
        case x5t_S256 = "x5t#S256"
        case typ
        case crit
        case enc
    }

    public var alg: String?
    public var jku: String?
    public var jwk: String?
    public var kid: String?
    public var x5u: String?
    public var x5t: String?
    public var x5t_S256: String?
    public var typ: String? // if present, should be "JWT"
    public var crit: String?
    public var enc: String?
}

public struct RegisteredClaims: Decodable {

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiration = "exp"
        case notBefore = "nbf"
        case issuedAt = "iat"
        case jwtID = "jti"
    }

    public let issuer: StringOrURI?
    public let subject: StringOrURI?
    public let audience: Audience?
    public let expiration: NumericDate?
    public let notBefore: NumericDate?
    public let issuedAt: NumericDate?
    public let jwtID: String?
}



public enum JOSEParameter: String {
    case typ = "typ"
    case alg = "alg"
    case enc = "enc"
    case cty = "cty"
}

public enum JWTClaim: String {
    case issuer = "iss"
    case subject = "sub"
    case audience = "aud"
    case expiration = "exp"
    case notBefore = "nbf"
    case issuedAt = "iat"
    case jwtID = "jti"
}

/// A JWT parser and builder.
///
/// See also: [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
public struct JWTComponents {
    /// An ASCII string composed from `header` + "." + `payload` + "." + `signature` where `header`, `payload` and `signature` are base64URL encoded.
    public typealias JWSCompactSerialization = String
    public typealias JSONObject = [String: Any]

    private enum JSONPart {
        case jsonObject(JSONObject)
        case json(Data)

        var base64URLEncodedString: String {
            switch self {
            case .jsonObject(let object):
                let data = try! JWTParser.encode(object)
                return data.base64URLEncodedString()
            case .json(let data):
                return data.base64URLEncodedString()
            }
        }

        var json: Data {
            switch self {
            case .jsonObject(let jsonObject):
                return try! JWTParser.encode(jsonObject)
            case .json(let data):
                return data
            }
        }

        var jsonPretty: String {
            let obj: JSONObject
            switch self {
            case .jsonObject(let jsonObject):
                obj = jsonObject
            case .json(let data):
                obj = try! JWTParser.decode(JSONObject.self, from: data)
            }
            let data = try! JWTParser.encode(obj, pretty: true)
            let string = String(data: data, encoding: .utf8)!
            return string
        }

        func getValue<Value: Decodable>(_ type: Value.Type, forField key: String) throws -> Value? {
            var obj: JSONObject
            switch self {
            case .jsonObject(let jsonObject):
                obj = jsonObject
            case .json(let data):
                obj = try JWTParser.decode(JSONObject.self, from: data)
            }
            guard let anyJSONValue = obj[key] else {
                return nil
            }
            let json = try JWTParser.encode(anyJSONValue)
            return try JWTParser.decode(Value.self, from: json)
        }

        mutating func setValue<Value: Encodable>(_ value: Value?, forField key: String) throws {
            var obj: JSONObject
            switch self {
            case .jsonObject(let jsonObject):
                obj = jsonObject
            case .json(let data):
                obj = try! JWTParser.decode(JSONObject.self, from: data)
            }
            let json = try JWTParser.encode(value)
            let anyJSONValue = try JWTParser.decode(from: json)
            obj[key] = anyJSONValue
            self = .jsonObject(obj)
        }
    }

    private var _header: JSONPart
    private var _payload: JSONPart?
    private var _signature: Data? // raw data

    /// Initializes a JWTComponents value.
    ///
    /// Initialisation checks if the JWT is wellformed but it performs no semantic checks. For example, it
    /// does not check if the JWT is expired when there is a `exp` claim set.
    /// - Parameters:
    ///   - jwt: A JWT in JWS Compact Serialization format.
    ///   - leeway: A small leeway in seconds, usually no more than a few minutes, to account for clock skew when validating expiration dates.
    /// - Throws: An error if the JWT is malformed.
    public init(jwt: JWSCompactSerialization, leeway: Int = 120) throws {
        let parts = jwt.split(separator: ".")
        // Note, the given string should be either a JWE (5 parts) or JWS (3 parts).
        // Currently, JWE is not supported
        self.leeway = leeway
        if parts.count == 5 {
            throw Self.error("JWE not supported")
        }
        guard parts.count == 2 || parts.count == 3 else {
            // If we get two parts, this is an "unsecured JWT".
            throw Self.error("malformed JWT: invalid number of parts")
        }
        do {
            // Validate the JOSE header and claims by parsing the JSON, which
            // just checks if they are syntactical correct.
            try Self.parseJOSEHeader(string: parts[0])
            _header = .json(try parts[0].base64URLDecodedData())

            try Self.parseClaimsForJWS(string: parts[1])
            let payload = try parts[1].base64URLDecodedData()
            _payload = .json(payload)

            _signature = parts.count == 3 ? try parts[2].base64URLDecodedData() : Data()
        } catch let underlyingError {
            throw Self.error(underlyingError: underlyingError)
        }
    }

    /// Initializes an empty JWTComponents value.
    public init() {
        leeway = 0
        _header = .jsonObject(JSONObject())
        _payload = nil
        _signature = nil
    }

    /// A small leeway in seconds, usually no more than a few minutes, to account for clock skew when validating expiration dates.
    public var leeway: Int {
        didSet {
            guard leeway <= 5*60, leeway >= 0 else {
                fatalError("leeway value out of range")
            }
        }
    }

    /// Returns a JWT as a JWS if it is wellformed. Otherwise returns `nil`.
    public var jwt: JWSCompactSerialization? {
        return try? jwtCompact()
    }

    /// Returns a JWT in a JWS Compact Serialization representation.
    ///
    /// The JWS Compact Serialization represents digitally signed or MACed content as a compact, URL-safe string.
    /// - Throws: An error when the JWT is malformed.
    /// - Returns: The valid JWT in JSON Compact Serialisation
    public func jwtCompact() throws -> JWSCompactSerialization {
        /// Attempt to returns a JWS
        guard let signature = self.signature, !signature.isEmpty else {
            throw error("JWT not signed")
        }
        guard let payload = self.payload else {
            throw error("missing payload")
        }
        // TODO: probably, we should verify and validate it before returning!
        return "\(self.header).\(payload).\(signature)"
    }

    /// Returns the header of the JWT as a base64URL string.
    public var header: Base64URLEncodedString {
        switch _header {
        case .jsonObject(let jsonObject):
            return try! JWTParser.encode(jsonObject).base64URLEncodedString()
        case .json(let data):
            return data.base64URLEncodedString()
        }
    }

    /// Returns the header as a JSON Object encode as a `[String: Any]`.
    public func header(as type: JSONObject.Type) throws -> JSONObject {
        switch _header {
        case .jsonObject(let jsonObject):
            return jsonObject
        case .json(let data):
            return try! JWTParser.header(data: data)
        }
    }

    /// Returns the header as a JSON Object encoded as a value of type `Header`.
    /// - Parameter type: The type of the structured header.
    /// - Throws: An error if the header could not be decoded to the given type.
    /// - Returns: The structured header.
    public func header<Header>(as type: Header.Type) throws -> Header where Header: Decodable {
        return try JWTParser.decode(Header.self, from: _header.json)
    }

    /// In case this is a JWS, returns the payload of the JWT as a base64URL string, otherwise returns `nil`
    public var payload: Base64URLEncodedString? {
        get { _payload?.base64URLEncodedString }
    }

    /// Returns a structured payload of the JWT .
    /// - Parameter type: The type of the structured payload.
    /// - Throws: An error if the payload could not be decoded to the given type.
    /// - Returns: The structured payload.
    public func payload<Claims>(as type: Claims.Type) throws -> Claims where Claims: Decodable {
        guard let payload = _payload else {
            throw error("no payload")
        }
        return try JWTParser.decode(Claims.self, from: payload.json)
    }

    /// Returns a structured payload of the JWT as a JSONObject.
    /// - Parameter type: The type of the structured payload.
    /// - Throws: An error if the payload could not be decoded to the given type.
    /// - Returns: The structured payload.
    public func payload(as type: JSONObject.Type) throws -> JSONObject {
        switch _payload {
        case .some(.jsonObject(let jsonObject)):
            return jsonObject
        case .some(.json(let data)):
            return try! JWTParser.decode(from: data) as! JSONObject
        case .none:
            throw error("no payload")
        }
    }

    /// In case this is a JWS, returns the signature of the JWT as a base64URL string, otherwise returns `nil`.
    public var signature: Base64URLEncodedString? {
        get { _signature?.base64URLEncodedString() }
    }

    /// In case of a JWS, returns the signature of the JWT as Data, otherwise it returns `nil`.
    public var signatureData: Data? {
        get { _signature }
    }


    // MARK: - Verification

    /// Verifies the JWT with the given verifier.
    ///
    /// Verification only checks if JWT is wellformed and if the signatur is valid. It does not make any semantic checks for the claims or header parameters.
    ///
    /// - Parameter verifier: A verifier.
    /// - Throws: An error if the JWT is not signed, or signature test fails, or the JWT is malformed.
    public func verify(with verifier: JWSVerifier) throws {
        do {
            let jwt = try self.jwtCompact()
            try verifier.verify(jwt: jwt)
        } catch let underlyingError {
            throw error(underlyingError: underlyingError)
        }
    }

//    /// Verifies the JWT with a verifier derived from the header values`alg`.
//    ///
//    /// Verification only checks if the signatur is valid. It does not make any semantic checks for the claims or header parameters.
//    /// - Throws: An error if the JWT is malformed or if no signing algorithn has been found, or if the
//    /// signing failed
//    @available(*, deprecated, message: "Use `verify:(verifier:)` instead")
//    public func verify(withKey data: Data) throws {
//        guard let algorithmName = try header(as: JOSEHeader.self).alg else {
//            throw error("no algorithm specfied in the JOSE header")
//        }
//        guard let algorithm = JWTAlgorithm(rawValue: algorithmName) else {
//            throw error("Algorithm \"\(algorithmName)\" not supported")
//        }
//        do {
//            let signer = try JWTFactory.createJWTVerifier(algorithm: algorithm, keyData: data)
//            try signer.verify(jwtComponents: self)
//
//        } catch let underlyingError{
//            throw error(underlyingError: underlyingError)
//        }
//    }

    // MARK: - Validation


    /// Validates registered claims.
    ///
    /// Validates these registered claims as follows:
    ///  - `exp`: ensure the current date is less than or equal the expiration date plus `leeway`.
    ///  - `nbf`: ensure the current date is greater than or equal the "not before date" minus `leeway`.
    ///
    /// - Throws: An error if any of the registered claims is not valid.
    public func validate() throws {
        try validateRegisteredClaimsForJWS()
    }

    /// Validates registered claims and calls the provided custom validation function.
    ///
    /// Validates these registered claims as follows:
    ///  - `exp`: ensure the current date is less than or equal the expiration date plus `leeway`.
    ///  - `nbf`: ensure the current date is greater than or equal the "not before date" minus `leeway`.
    ///
    /// - Parameters:
    ///   - headerType: The type of the header.
    ///   - claimsType: The type of the claims.
    ///   - validate: A custom validation function.
    /// - Throws: An error if the JWT is not valid.
    public func validate<Header, Claims>(forHeader headerType: Header.Type,
                                  claims claimsType: Claims.Type,
                                  validate: (Header, Claims) throws -> Void) throws
    where Header: Decodable, Claims: Decodable {
        try validateRegisteredClaimsForJWS()
        try validate(try header(as: headerType), try payload(as: claimsType))
    }

    /// Verifies if the JWT is signed and then validates the claims.
    ///
    /// - Parameters:
    ///   - headerType: The type of the header.
    ///   - claimsType: The type of the claims.
    ///   - validate: A custom validation function.
    /// - Throws: An error if the JWT is not valid.
    public func validate<Header, Claims>(with verifier: JWSVerifier,
                                         forHeader headerType: Header.Type,
                                         claims claimsType: Claims.Type,
                                         validate: (Header, Claims) throws -> Void) throws
    where Header: Decodable, Claims: Decodable {
        try verify(with: verifier)
        try validate(try header(as: headerType), try payload(as: claimsType))
    }

//    @available(*, deprecated, message: "Use `validate(with:forHeader:claims:validate:)` instead")
//    public func validate<Header, Claims>(withKey data: Data,
//                                        forHeader headerType: Header.Type,
//                                        claims claimsType: Claims.Type,
//                                        validate: (Header, Claims) throws -> Void) throws
//    where Header: Decodable, Claims: Decodable {
//        try verify(withKey: data)
//        try validate(try header(as: headerType), try payload(as: claimsType))
//    }

    // MARK: - Signing

    /// Signs the JWT with the given signer.
    ///
    /// If signing is successfull, it will set the `typ` and the `alg` parameter in the header accordingly.
    /// - Parameter signer: A signer.
    /// - Throws: An error if the JWT is malformed.
    public mutating func sign(signer: JWSSigner) throws {
        do {
            let newComponents = try signer.sign(jwtComponents: self)
            self = newComponents
        } catch let underlyingError {
            throw error(underlyingError: underlyingError)
        }
    }

    /// Signs the JWT with a signer derived from the header values`alg`.
    ///
    /// - Throws: An error if the JWT is malformed or if no signing algorithn has been found, or if the
    /// signing failed
    public mutating func sign(withKey data: Data) throws {
        guard let algorithmName = try header(as: JOSEHeader.self).alg else {
            throw error("no algorithm specfied in the JOSE header")
        }
        guard let algorithm = JWTAlgorithm(rawValue: algorithmName) else {
            throw error("Algorithm \"\(algorithmName)\" not supported")
        }
        do {
            let signer = try JWTFactory.createJWTSigner(algorithm: algorithm, keyData: data)
            let newComponents = try signer.sign(jwtComponents: self)
            self = newComponents

        } catch let underlyingError{
            throw error(underlyingError: underlyingError)
        }
    }


    // MARK: - Private

    /// Validates registered claims.
    ///
    /// Validate the following claims:
    ///  - `exp`: ensure the current date is less than or equal the expiration date plus `leeway`.
    ///  - `nbf`: ensure the current date is greater than or equal the "not before date" minus `leeway`.
    private func validateRegisteredClaimsForJWS() throws {
        let claims = try payload(as: RegisteredClaims.self)

        if let exp = claims.expiration {
            guard Date().timeIntervalSince1970 <= Double(exp + leeway) else {
                throw error("JWT expired at \(Date(timeIntervalSince1970: Double(exp)))")
            }
        }
        if let nbf = claims.notBefore {
            guard Date().timeIntervalSince1970 >= Double(nbf - leeway) else {
                throw error("cannot process JWT before \(Date(timeIntervalSince1970: Double(nbf))) ")
            }
        }
    }

    private static func parseJOSEHeader<Base64URLEncodedString: StringProtocol>(string: Base64URLEncodedString) throws {
        // TODO: currently, we cannot test if the encoded representation is "compact".
        let _ = try JWTParser.part(part: string, PartType: JOSEHeader.self)
    }

    private static func parseClaimsForJWS<Base64URLEncodedString: StringProtocol>(string: Base64URLEncodedString) throws {
        // TODO: currently, we cannot test if the encoded representation is "compact".
        let _ = try JWTParser.part(part: string, PartType: RegisteredClaims.self)
    }

}

public extension JWTComponents {

    func getValue<Value: Decodable>(_ type: Value.Type, forClaim claim: JWTClaim) throws -> Value? {
        try self._payload?.getValue(Value.self, forField: claim.rawValue)
    }

    func getValue<Value: Decodable>(_ type: Value.Type, forClaim string: String) throws -> Value? {
        try self._payload?.getValue(Value.self, forField: string)
    }

    func getValue<Value: Decodable>(_ type: Value.Type, forHeaderParameter param: JOSEParameter) throws -> Value? {
        try self._header.getValue(Value.self, forField: param.rawValue)
    }

    func getValue<Value: Decodable>(_ type: Value.Type, forHeaderParameter string: String) throws -> Value? {
        try self._header.getValue(Value.self, forField: string)
    }
}

public extension JWTComponents {

    mutating func setValue<Value: Encodable>(_ value: Value?, forClaim claim: JWTClaim) throws {
        _signature = nil
        if self._payload == nil {
            self._payload = .jsonObject(JSONObject())
        }
        try self._payload!.setValue(value, forField: claim.rawValue)
    }

    mutating func setValue<Value: Encodable>(_ value: Value?, forClaim string: String) throws {
        _signature = nil
        if self._payload == nil {
            self._payload = .jsonObject(JSONObject())
        }
        try self._payload!.setValue(value, forField: string)
    }

    mutating func setValue<Value: Encodable>(_ value: Value?, forHeaderParameter param: JOSEParameter) throws {
        _signature = nil
        try self._header.setValue(value, forField: param.rawValue)
    }

    mutating func setValue<Value: Encodable>(_ value: Value?, forHeaderParameter string: String) throws {
        _signature = nil
        try self._header.setValue(value, forField: string)
    }
}

public extension JWTComponents {

    /// Set  or get the Issuer claim (`iss`).
    ///
    /// The "iss" (Issuer) claim identifies the principal that issued the JWT.
    var issuer: StringOrURI? {
        get {
            try! self.getValue(StringOrURI.self, forClaim: .issuer)
        }
        set {
            try! self.setValue(newValue, forClaim: .issuer)
        }
    }

    /// Set or get the Subject claim (`sub`).
    ///
    /// The "sub" (Subject) claim identifies the principal that is the subject the claims are referring to.
    var subject: StringOrURI? {
        get {
            try! self.getValue(StringOrURI.self, forClaim: .subject)
        }
        set {
            try! self.setValue(newValue, forClaim: .subject)
        }
    }

    /// Set or get the Audience claim (`aud`).
    ///
    /// The "aud" (Audience) claim identifies the recipients that the JWT is intended for.
    var audience: Audience? {
        get {
            try! self.getValue(Audience.self, forClaim: .audience)
        }
        set {
            try! self.setValue(newValue, forClaim: .audience)
        }
    }

    /// Set or get the Expiration Time claim (`exp`).
    ///
    /// The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
    var expiration: NumericDate? {
        get {
            try! self.getValue(NumericDate.self, forClaim: .expiration)
        }
        set {
            try! self.setValue(newValue, forClaim: .expiration)
        }
    }

    /// Set or get the "Not Before" claim (`nbf`).
    ///
    /// The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
    var notBefore: NumericDate? {
        get {
            try! self.getValue(NumericDate.self, forClaim: .notBefore)
        }
        set {
            try! self.setValue(newValue, forClaim: .notBefore)
        }
    }

    /// Set or get the "issued at" claim (`iat`).
    ///
    /// The "iat" (issued at) claim identifies the time at which the JWT was issued.
    var issuedAt: NumericDate? {
        get {
            try! self.getValue(NumericDate.self, forClaim: .issuedAt)
        }
        set {
            try! self.setValue(newValue, forClaim: .issuedAt)
        }
    }

    /// Set or get the "JWT ID" claim (`jti`).
    ///
    /// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
    var jwtID: String? {
        get {
            try! self.getValue(String.self, forClaim: .jwtID)
        }
        set {
            try! self.setValue(newValue, forClaim: .jwtID)
        }
    }
}

extension JWTComponents: CustomStringConvertible {
    public var description: String {
        let parts = [_header.jsonPretty, _payload?.jsonPretty ?? "", _signature?.base64URLEncodedString() ?? ""]
        return parts.joined(separator: ".\n")
    }
}

// MARK: - Internal

/// Extensions which expose an API for Signers only.
extension JWTComponents {
    mutating func set(header: Base64URLEncodedString, payload: Base64URLEncodedString, signature: Data) {
        _header = .json(try! header.base64URLDecodedData())
        _payload = .json(try! payload.base64URLDecodedData())
        _signature = signature
    }
}

extension JWTParser {

    static func header<Header: Decodable>(jwt: Base64URLEncodedString, headerType: Header.Type) throws -> Header {
        guard let header = jwt.split(separator: ".").first else {
            throw error("no header in JWT")
        }
        return try JWTParser.part(part: header, PartType: Header.self)
    }

    static func header(data: Data) throws -> JWTComponents.JSONObject {
        return try decode(JWTComponents.JSONObject.self, from: data)
    }

    static func claims<ClaimSet: Decodable>(jwt: Base64URLEncodedString, claimsType: ClaimSet.Type) throws -> ClaimSet {
        guard let payload = jwt.split(separator: ".").dropFirst().first else {
            throw error("no payload in JWT")
        }
        return try JWTParser.part(part: payload, PartType: ClaimSet.self)
    }

    static func signatureEncoded(jwt: Base64URLEncodedString) throws -> Substring {
        guard let signature = jwt.split(separator: ".").dropFirst(2).first else {
            throw error("no signature in JWT")
        }
        return signature
    }

    static func signature(jwt: Base64URLEncodedString) throws -> Data {
        return try self.signatureEncoded(jwt: jwt).base64URLDecodedData()
    }

    static func part<Part: Decodable, Base64URLEncodedString: StringProtocol>(part: Base64URLEncodedString, PartType: Part.Type) throws -> Part {
        let json = try part.base64URLDecodedData()
        return try decode(Part.self, from: json)
    }

    static func validateJSON<Part: Decodable, Base64URLEncodedString: StringProtocol>(part: Base64URLEncodedString, PartType: Part.Type) throws {
        let json = try part.base64URLDecodedData()
        try JWTParser.validateJSON(json)
    }
}

extension JWTComponents: ErrorThrowing {}

extension JWTComponents {
    public struct StringOrURIValue: Codable, ExpressibleByStringLiteral, Equatable, ErrorThrowing {
        let value: String

        public init(stringLiteral value: String) {
            try! self.init(string: value)
        }

        public init(string: String) throws {
            try Self.validateStringOrURI(string: string)
            self.value = string
        }

        public init(from decoder: Decoder) throws {
            let singleValueContainer = try decoder.singleValueContainer()
            let string = try singleValueContainer.decode(String.self)
            do {
                try self.init(string: string)
            } catch {
                let context = DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Could not decode StringOrURI value.", underlyingError: error)
                throw DecodingError.typeMismatch(StringOrURIValue.self, context)
            }
        }

        public func encode(to encoder: Encoder) throws {
            var singleValueContainer = encoder.singleValueContainer()
            try singleValueContainer.encode(value)
        }

        static func validateStringOrURI(string: String) throws {
            guard (URL(string: string) != nil) || string.contains(":") == false else {
                throw Self.error("malformed StringOrURI")
            }
        }

        static func == (lhs: Self, rhs: String) -> Bool {
            return lhs.value == rhs
        }

        static func == (lhs: String, rhs: Self) -> Bool {
            return lhs == rhs.value
        }
    }

    public struct MultiValue<Element: Codable>: Codable {
        let values: [Element]

        init(value: Element) {
            self.values = [value]
        }

        public init(values: [Element]) {
            self.values = values
        }

        public init(from decoder: Decoder) throws {
            let singleValueContainer = try decoder.singleValueContainer()
            do {
                self.init(value: try singleValueContainer.decode(Element.self))
            } catch DecodingError.typeMismatch {
                do {
                    self.init(values: try singleValueContainer.decode([Element].self))
                } catch {
                    let context = DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Could not find either value of type '\(Element.self)' or '[\(Element.self)]'.", underlyingError: error)
                    throw DecodingError.typeMismatch(MultiValue.self, context)
                }
            }
        }

        public func encode(to encoder: Encoder) throws {
            switch self.values.count {
            case 1:
                var container = encoder.singleValueContainer()
                try container.encode(values[0])
            default:
                var container = encoder.singleValueContainer()
                try container.encode(values)
            }
        }
    }
}

extension JWTComponents.MultiValue: Equatable where Element: Equatable {}

extension JWTComponents.MultiValue: ExpressibleByStringLiteral, ExpressibleByExtendedGraphemeClusterLiteral, ExpressibleByUnicodeScalarLiteral where Element: ExpressibleByStringLiteral,
                                                                     Element.StringLiteralType == StringLiteralType,
                                                                     Element.ExtendedGraphemeClusterLiteralType == StringLiteralType,
                                                                     Element.UnicodeScalarLiteralType == StringLiteralType
{
    public init(stringLiteral value: String) {
        let value = Element(stringLiteral: value)
        self.init(value: value)
    }
    public init(extendedGraphemeClusterLiteral value: String) {
        let value = Element(extendedGraphemeClusterLiteral: value)
        self.init(value: value)
    }
    public init(unicodeScalarLiteral value: String) {
        let value = Element(unicodeScalarLiteral: value)
        self.init(value: value)
    }
}

extension JWTComponents.MultiValue: ExpressibleByArrayLiteral where Element: ExpressibleByStringLiteral, Element.StringLiteralType == String {
    public typealias ArrayLiteralElement = String

    public init(arrayLiteral elements: Self.ArrayLiteralElement...) {
        let values = elements.map { Element(stringLiteral: $0) }
        self.init(values: values)
    }

}
