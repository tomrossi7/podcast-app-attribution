// Minting a Verified App Attribution token in Swift. CryptoKit only; drop this file into an app.
//
//     let token = try Attribution.mint(key: key, kid: "2026-11", iss: "https://exampleplayer.com", url: url)
//     let request = URLRequest(url: URL(string: Attribution.attach(token, to: url))!)
//
// Leave `url` out for a session token that can be attached to any request until it expires.
//
// Where the key lives is up to you. The specification asks that signing keys be protected from
// extraction; minting on infrastructure you control and handing the token to the app is one way.

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // swift-crypto: the same API where CryptoKit is not available
#endif

public enum Attribution {
    // CWT and CAT claim labels (IANA CWT Claims registry).
    static let iss = 1, aud = 3, exp = 4, iat = 6, cti = 7, catv = 310, catu = 312, catm = 313
    // COSE header labels and the ES256 algorithm value.
    static let alg = 1, kid = 4, es256 = -7

    public static func mint(
        key: P256.Signing.PrivateKey,
        kid: String,
        iss: String,
        url: String? = nil,
        methods: [String] = ["GET", "HEAD"],
        aud: String? = nil,
        lifetime: Int = 300,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> String {
        var generator = SystemRandomNumberGenerator() // cryptographically secure
        let tokenID = Data((0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) })

        var claims: [(CBOR, CBOR)] = [
            (.int(Self.iss), .text(iss)),
            (.int(Self.exp), .int(now + lifetime)),
            (.int(Self.iat), .int(now)),
            (.int(Self.cti), .bytes(tokenID)),
            (.int(Self.catv), .int(1)),
        ]
        if let aud { claims.append((.int(Self.aud), .text(aud))) }
        if let url {
            claims.append((.int(Self.catu), exactURL(url)))
            claims.append((.int(Self.catm), .array(methods.map(CBOR.text))))
        }

        // COSE_Sign1 (RFC 9052 §4.2): [protected header as bytes, unprotected header, payload, signature].
        // The signature covers the Sig_structure of §4.4 with empty external data.
        let protected = CBOR.map([(.int(Self.alg), .int(Self.es256)), (.int(Self.kid), .bytes(Data(kid.utf8)))]).encoded
        let payload = CBOR.map(claims).encoded
        let toBeSigned = CBOR.array([.text("Signature1"), .bytes(protected), .bytes(Data()), .bytes(payload)]).encoded
        let signature = try key.signature(for: toBeSigned).rawRepresentation // SHA-256, then 64 bytes: r then s

        let token = CBOR.tagged(18, .array([.bytes(protected), .map([]), .bytes(payload), .bytes(signature)])).encoded
        return token.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Appends the token, leaving the URL alone if it already carries one.
    public static func attach(_ token: String, to url: String) -> String {
        let query = split(url).query
        if !extractTokens(query).tokens.isEmpty { return url }
        return url + (query == nil ? "?" : "&") + "CAT=" + token
    }

    /// A catu that matches exactly this URL: scheme, host, path and query, after removing any CAT
    /// parameter and normalizing. Port is left out, so any port matches.
    static func exactURL(_ url: String) -> CBOR {
        var parts = split(url)
        parts.query = extractTokens(parts.query).query
        let n = normalize(parts)
        func exact(_ value: String) -> CBOR { .map([(.int(0), .text(value))]) }
        return .map([
            (.int(0), exact(n.scheme)),
            (.int(1), exact(n.host)),
            (.int(3), exact(n.path)),
            (.int(4), exact(n.query ?? "")),
        ])
    }
}

// MARK: - CBOR

/// The subset of CBOR (RFC 8949) a token uses, encoded deterministically.
indirect enum CBOR {
    case int(Int)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([(CBOR, CBOR)])
    case tagged(UInt64, CBOR)

    var encoded: Data {
        switch self {
        case .int(let n):
            return n >= 0 ? Self.head(0, UInt64(n)) : Self.head(1, UInt64(-1 - n))
        case .bytes(let data):
            return Self.head(2, UInt64(data.count)) + data
        case .text(let string):
            let utf8 = Data(string.utf8)
            return Self.head(3, UInt64(utf8.count)) + utf8
        case .array(let items):
            return items.reduce(Self.head(4, UInt64(items.count))) { $0 + $1.encoded }
        case .map(let pairs):
            return pairs.reduce(Self.head(5, UInt64(pairs.count))) { $0 + $1.0.encoded + $1.1.encoded }
        case .tagged(let tag, let value):
            return Self.head(6, tag) + value.encoded
        }
    }

    /// The initial byte: major type in the top 3 bits, then the argument in its shortest form.
    private static func head(_ major: UInt8, _ n: UInt64) -> Data {
        let m = major << 5
        func bigEndian(_ count: Int) -> [UInt8] { (0..<count).reversed().map { UInt8(truncatingIfNeeded: n >> (8 * UInt64($0))) } }
        switch n {
        case 0..<24: return Data([m | UInt8(n)])
        case 24..<0x100: return Data([m | 24] + bigEndian(1))
        case 0x100..<0x1_0000: return Data([m | 25] + bigEndian(2))
        case 0x1_0000..<0x1_0000_0000: return Data([m | 26] + bigEndian(4))
        default: return Data([m | 27] + bigEndian(8))
        }
    }
}

// MARK: - URLs
// Handled as strings on purpose: URL and URLComponents rewrite what they parse.

extension Attribution {
    struct URLParts {
        var scheme = "", host = "", port = "", path = ""
        var query: String?
    }

    /// RFC 3986 §3: scheme, authority (host and port), path and query.
    static func split(_ url: String) -> URLParts {
        var parts = URLParts()
        var rest = Substring(url)
        if let colon = rest.firstIndex(of: ":"), colon != rest.startIndex, !rest[..<colon].contains(where: { "/?#".contains($0) }) {
            parts.scheme = String(rest[..<colon])
            rest = rest[rest.index(after: colon)...]
        }
        if rest.hasPrefix("//") {
            rest = rest.dropFirst(2)
            let end = rest.firstIndex(where: { "/?#".contains($0) }) ?? rest.endIndex
            var authority = rest[..<end]
            rest = rest[end...]
            if let at = authority.lastIndex(of: "@") { authority = authority[authority.index(after: at)...] }
            // host[:port]; an IPv6 literal keeps its brackets and its colons.
            if let colon = authority.lastIndex(of: ":"), !authority[colon...].contains("]") {
                parts.host = String(authority[..<colon])
                parts.port = String(authority[authority.index(after: colon)...])
            } else {
                parts.host = String(authority)
            }
        }
        if let fragment = rest.firstIndex(of: "#") { rest = rest[..<fragment] }
        if let question = rest.firstIndex(of: "?") {
            parts.query = String(rest[rest.index(after: question)...])
            rest = rest[..<question]
        }
        parts.path = String(rest)
        return parts
    }

    /// The values of the CAT parameters in a query, and the query without them. The query is
    /// split on "&"; a name is everything before the first "=", percent-decoded once.
    static func extractTokens(_ query: String?) -> (tokens: [String], query: String?) {
        guard let query else { return ([], nil) }
        var tokens: [String] = [], rest: [Substring] = []
        for field in query.split(separator: "&", omittingEmptySubsequences: false) {
            let pair = field.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let name = String(pair.first ?? "")
            if (name.removingPercentEncoding ?? name) == "CAT" {
                tokens.append(pair.count > 1 ? String(pair[1]) : "")
            } else {
                rest.append(field)
            }
        }
        return (tokens, rest.isEmpty ? nil : rest.joined(separator: "&"))
    }

    /// RFC 9110 §4.2.3, then RFC 3986 §6.2.2 and §6.2.3.
    static func normalize(_ parts: URLParts) -> URLParts {
        let scheme = parts.scheme.lowercased()
        let path = removeDotSegments(percentNormalize(parts.path))
        return URLParts(
            scheme: scheme,
            host: percentNormalize(parts.host).lowercased(),
            port: parts.port == ["http": "80", "https": "443"][scheme] ? "" : parts.port,
            path: path.isEmpty ? "/" : path,
            query: parts.query.map(percentNormalize)
        )
    }

    /// Uppercase the hex digits of percent-escapes and decode the ones that stand for unreserved
    /// characters (letters, digits, "-", ".", "_", "~").
    static func percentNormalize(_ string: String) -> String {
        let bytes = Array(string.utf8)
        func hex(_ byte: UInt8) -> UInt8? {
            switch byte {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
            default: return nil
            }
        }
        func unreserved(_ byte: UInt8) -> Bool {
            switch byte {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "0")...UInt8(ascii: "9"): return true
            default: return "-._~".utf8.contains(byte)
            }
        }
        var out: [UInt8] = []
        var i = 0
        while i < bytes.count {
            if bytes[i] == UInt8(ascii: "%"), i + 2 < bytes.count, let high = hex(bytes[i + 1]), let low = hex(bytes[i + 2]) {
                let value = high << 4 | low
                if unreserved(value) {
                    out.append(value)
                } else {
                    out += Array(String(format: "%%%02X", value).utf8)
                }
                i += 3
            } else {
                out.append(bytes[i])
                i += 1
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// RFC 3986 §5.2.4.
    static func removeDotSegments(_ path: String) -> String {
        var input = Substring(path)
        var out: [Substring] = []
        while !input.isEmpty {
            if input.hasPrefix("../") {
                input = input.dropFirst(3)
            } else if input.hasPrefix("./") || input.hasPrefix("/./") {
                input = input.dropFirst(2)
            } else if input == "/." {
                input = "/"
            } else if input.hasPrefix("/../") {
                input = input.dropFirst(3)
                _ = out.popLast()
            } else if input == "/.." {
                input = "/"
                _ = out.popLast()
            } else if input == "." || input == ".." {
                input = ""
            } else {
                let end = input.dropFirst().firstIndex(of: "/") ?? input.endIndex
                out.append(input[..<end])
                input = input[end...]
            }
        }
        return out.joined()
    }
}
