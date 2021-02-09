import Foundation

// Encapsulates the actual JSONEncoder/JSONDecoder implementation. This makes it
// easier to switch to other implementations, like https://swiftpackageregistry.com/swift-extras/swift-extras-json,
// if Foundation is not available, or for other reasons.
//
// The Foundation JSONEncoder's concrete output encoding (UTF-8, UTF-16LE, etc.)
// isn't documented and cannot be configured. In fact, it follows best practices
// and thus it uses actually UTF-8, but strictly this is an implementation detail.
//
// For JWT we _require_ it to be UTF-8!
struct JWTParser {
    private static let decoder = JSONDecoder()
    private static let encoder = JSONEncoder()

    static func decode<T>(_ type: T.Type, from data: Data) throws -> T where T: Decodable {
        return try decoder.decode(type, from: data)
    }

    static func decode(from data: Data) throws -> Any {
        let anyJSONValue = try JSONSerialization.jsonObject(with: data, options: .allowFragments)
        return anyJSONValue
    }

    static func decode<D: Collection>(_ type: D.Type, from data: Data) throws -> D where D.Element == (key: String, value: Any) {
        let any = try JSONSerialization.jsonObject(with: data)
        guard let dictionary = any as? D else {
            throw error("could not decode data into Dictionary")
        }
        return dictionary
    }

    static func encode<T>(_ value: T, pretty: Bool = false) throws -> Data where T: Encodable {
        encoder.outputFormatting = pretty ? [.prettyPrinted] : []
        return try encoder.encode(value)
    }

    static func encode(_ jsonObject: [String: Any], pretty: Bool = false) throws -> Data {
        let options: JSONSerialization.WritingOptions = pretty ? [.prettyPrinted, .fragmentsAllowed] : [.fragmentsAllowed]
        let data = try JSONSerialization.data(withJSONObject: jsonObject, options: options)
        return data
    }

    static func encode(_ object: Any, pretty: Bool = false) throws -> Data {
        let options: JSONSerialization.WritingOptions = pretty ? [.prettyPrinted, .fragmentsAllowed] : [.fragmentsAllowed]
        let data = try JSONSerialization.data(withJSONObject: object, options: options)
        return data
    }

    static func validateJSONObject(_ jsonObject: [String: Any]) throws {
        guard JSONSerialization.isValidJSONObject(jsonObject) else {
            throw error("object \(jsonObject) is not valid JSON")
        }
    }

    static func validateJSON(_ json: Data) throws {
        struct AnyObject: Decodable {}
        let _ = try decoder.decode(AnyObject.self, from: json)
    }

}

extension JWTParser: ErrorThrowing {}
