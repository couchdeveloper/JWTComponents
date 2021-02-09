/// Defines the type of error returned from functions.
struct Error: Swift.Error, CustomStringConvertible, CustomDebugStringConvertible {
    var description: String {
        let prefix = "\(subjectType).\(function) failed: "
        let error = !message.isEmpty ? message : underlyingError != nil ? String(describing: underlyingError!) : "no description available"
        return prefix + error
    }
    var debugDescription: String {
        let errMsg = !message.isEmpty ? " with error: \(message)" : ""
        var msg = "\(subjectType).\(function) failed\(errMsg).\n\tSubject: \(subjectDescription)\n\tFile: \(file)[\(line)]."
        if let underlyingError = self.underlyingError {
            msg = msg + "\n\tUnderlying error: " + String(reflecting: underlyingError)
        }
        return msg
    }

    let message: String
    let file: StaticString
    let subjectDescription: String
    let subjectType: String
    let function: StaticString
    let line: UInt
    let underlyingError: Swift.Error?


    init(_ message: @autoclosure () -> String = String(), underlyingError: Swift.Error? = nil, subjectType: String, subjectDescription: String, function: StaticString = #function, file: StaticString = #file, line: UInt = #line) {
        self.message = message()
        self.subjectType = subjectType
        self.subjectDescription = subjectDescription
        self.function = function
        self.file = file
        self.line = line
        self.underlyingError = underlyingError
    }
}

protocol ErrorThrowing {}

extension ErrorThrowing {
    func error(_ message: @autoclosure () -> String, underlyingError: Swift.Error? = nil, function: StaticString = #function, file: StaticString = #file, line: UInt = #line) -> Swift.Error {
        return Error(message(), underlyingError: underlyingError, subjectType: "\(type(of: self))", subjectDescription: String(reflecting: self), function: function, file: file, line: line)
    }

    func error(underlyingError: Swift.Error, function: StaticString = #function, file: StaticString = #file, line: UInt = #line) -> Swift.Error {
        return Error("", underlyingError: underlyingError, subjectType: "\(type(of: self))", subjectDescription: String(reflecting: self), function: function, file: file, line: line)
    }

    static func error(underlyingError: Swift.Error, function: StaticString = #function, file: StaticString = #file, line: UInt = #line) -> Swift.Error {
        return Error("", underlyingError: underlyingError, subjectType: "\(Self.self)", subjectDescription: "", function: function, file: file, line: line)
    }

    static func error(_ message: @autoclosure () -> String, underlyingError: Swift.Error? = nil, function: StaticString = #function, file: StaticString = #file, line: UInt = #line) -> Swift.Error {
        return Error(message(), underlyingError: underlyingError, subjectType: "\(Self.self)", subjectDescription: "\(Self.self)", function: function, file: file, line: line)
    }
}
