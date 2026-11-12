// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

import Foundation

/// A scripted list of core requests. Bodies are data, not code, so the harness follows the
/// request bodies of the SDK without being recompiled when one gains a field.
///
/// `${name}` in any string is replaced by a saved variable. `save` copies values out of a
/// reply by dot path (`a.b.0.c`) into variables for later steps and for the result file.
struct Scenario: Decodable {
    struct Step: Decodable {
        let method: String
        /// Account variable or literal; omitted for process-level methods.
        let account: String?
        let body: JSONValue?
        /// Operation key of a mutation. It is chosen here once and never regenerated.
        let operationId: String?
        let deadlineMs: UInt64?
        let save: [String: String]?
        /// Dot paths that must exist in the reply, with the value they must equal.
        let expect: [String: String]?

        enum CodingKeys: String, CodingKey {
            case method, account, body, save, expect
            case operationId = "operation_id"
            case deadlineMs = "deadline_ms"
        }
    }

    /// Display name of the created account.
    let displayName: String
    /// Test-only data passphrase of the harness account. Never a real user's secret.
    let passphrase: String
    /// Variables known before the run (peer identifiers written by the driver script).
    let variables: [String: String]?
    /// Before the account exists: add and confirm the local gateway's node.
    let setup: [Step]
    /// After the ceremony: add the peer and send the first direct message.
    let afterCreate: [Step]
    /// After the kill: prove the first message survived and send a second one.
    let afterRestart: [Step]
    /// After a suspend/resume cycle: send once more over the resumed session.
    let afterResume: [Step]

    enum CodingKeys: String, CodingKey {
        case passphrase, variables, setup
        case displayName = "display_name"
        case afterCreate = "after_create"
        case afterRestart = "after_restart"
        case afterResume = "after_resume"
    }
}

/// Minimal JSON tree, so step bodies keep their exact shape.
enum JSONValue: Decodable {
    case null
    case bool(Bool)
    case number(Double)
    case integer(Int64)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            self = .object(try container.decode([String: JSONValue].self))
        }
    }

    /// Foundation value with `${name}` replaced in every string.
    func resolved(_ variables: [String: String]) throws -> Any {
        switch self {
        case .null: return NSNull()
        case .bool(let value): return value
        case .number(let value): return value
        case .integer(let value): return value
        case .string(let value): return try substitute(value, variables)
        case .array(let values): return try values.map { try $0.resolved(variables) }
        case .object(let fields):
            return try fields.mapValues { try $0.resolved(variables) }
        }
    }
}

enum ScenarioError: Error, CustomStringConvertible {
    case unknownVariable(String)
    case missingPath(method: String, path: String)
    case unexpected(method: String, path: String, wanted: String, found: String)
    case waitEnded(method: String, claimed: Bool)

    var description: String {
        switch self {
        case .unknownVariable(let name): return "unknown variable ${\(name)}"
        case .missingPath(let method, let path): return "\(method): reply has no \(path)"
        case .unexpected(let method, let path, let wanted, let found):
            return "\(method): \(path) is \(found), wanted \(wanted)"
        case .waitEnded(let method, let claimed):
            return "\(method): wait ended, claimed=\(claimed)"
        }
    }
}

/// Replace every `${name}`. `${now}` is the Unix time in seconds and `${uuid}` a fresh UUID.
func substitute(_ text: String, _ variables: [String: String]) throws -> String {
    var result = ""
    var rest = Substring(text)
    while let open = rest.range(of: "${") {
        result += rest[rest.startIndex..<open.lowerBound]
        guard let close = rest[open.upperBound...].firstIndex(of: "}") else {
            result += rest[open.lowerBound...]
            return result
        }
        let name = String(rest[open.upperBound..<close])
        switch name {
        case "now": result += String(Int(Date().timeIntervalSince1970))
        case "uuid": result += UUID().uuidString.lowercased()
        default:
            guard let value = variables[name] else {
                throw ScenarioError.unknownVariable(name)
            }
            result += value
        }
        rest = rest[rest.index(after: close)...]
    }
    result += rest
    return result
}

/// Walk `a.b.0.c` through dictionaries and arrays.
func lookup(_ root: Any, path: String) -> Any? {
    var current: Any = root
    for part in path.split(separator: ".") {
        if let object = current as? [String: Any], let next = object[String(part)] {
            current = next
        } else if let array = current as? [Any], let index = Int(part), array.indices.contains(index) {
            current = array[index]
        } else {
            return nil
        }
    }
    return current
}

func text(_ value: Any) -> String {
    if let string = value as? String { return string }
    if let number = value as? NSNumber { return number.stringValue }
    if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
        let string = String(data: data, encoding: .utf8)
    {
        return string
    }
    return "\(value)"
}
