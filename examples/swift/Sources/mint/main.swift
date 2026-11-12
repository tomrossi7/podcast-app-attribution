// Mints a token with a private JWK and prints the URL to request, or the bare token for a
// session token.
//
//     swift run mint <private-keys.json> <kid> <iss> [url]

import Attribution
import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

let arguments = CommandLine.arguments.dropFirst()
guard arguments.count >= 3 else {
    FileHandle.standardError.write(Data("usage: mint <private-keys.json> <kid> <iss> [url]\n".utf8))
    exit(2)
}
let (file, kid, iss) = (arguments[arguments.startIndex], arguments[arguments.startIndex + 1], arguments[arguments.startIndex + 2])
let url = arguments.count > 3 ? arguments[arguments.startIndex + 3] : nil

// A JWK's "d" is the private scalar, base64url-encoded: exactly what CryptoKit calls the raw representation.
struct KeySet: Decodable {
    struct Key: Decodable { let kid: String; let d: String }
    let keys: [Key]
}
let keySet = try JSONDecoder().decode(KeySet.self, from: Data(contentsOf: URL(fileURLWithPath: file)))
guard let jwk = keySet.keys.first(where: { $0.kid == kid }) else { fatalError("no key named \(kid)") }
var base64 = jwk.d.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
let key = try P256.Signing.PrivateKey(rawRepresentation: Data(base64Encoded: base64)!)

let token = try Attribution.mint(key: key, kid: kid, iss: iss, url: url)
print(url.map { Attribution.attach(token, to: $0) } ?? token)
