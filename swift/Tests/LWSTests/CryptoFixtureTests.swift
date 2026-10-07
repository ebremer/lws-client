// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import LWS

/// The shared cryptographic fixtures: did:key, JWT credentials, test keys and the RFC 9421 webhook vectors.
@Suite struct CryptoFixtureTests {
    @Test(arguments: Fixtures.names("did-key.json", "vectors"))
    func didKeyDerivation(name: String) throws {
        let v = Fixtures.cases("did-key.json", "vectors").first { $0["name"]?.stringValue == name }!
        let key = try VerificationKey(jwk: v["publicJwk"]!.object)
        #expect(try DIDKey.did(for: key) == v["did"]!.str)
        #expect(try DIDKey.keyID(for: key) == v["kid"]!.str)
        #expect(try DIDKey.keyID(forDID: v["did"]!.str) == v["kid"]!.str)
        #expect(try DIDKey.did(forJWK: v["publicJwk"]!.object) == v["did"]!.str)
        let decoded = try DIDKey.publicKey(v["kid"]!.str)
        #expect(decoded.jwk == key.jwk)
    }

    @Test(arguments: Fixtures.names("jwt.json", "vectors"))
    func jwtCredentialsVerify(name: String) throws {
        let v = Fixtures.cases("jwt.json", "vectors").first { $0["name"]?.stringValue == name }!
        let key = try VerificationKey(jwk: v["publicJwk"]!.object)
        let jwt = v["jwt"]!.str
        #expect(JWT.verify(jwt, key: key))
        #expect(JSONValue.object(try JWT.decodeHeader(jwt)) == v["header"]!)
        #expect(JSONValue.object(try JWT.decodeClaims(jwt)) == v["claims"]!)
        #expect(JWT.expiration(jwt) == Date(timeIntervalSince1970: TimeInterval(v["claims"]!["exp"]!.intValue!)))
        var chars = Array(jwt)
        chars[chars.count - 4] = chars[chars.count - 4] == "A" ? "B" : "A"
        #expect(!JWT.verify(String(chars), key: key))
        // The kid in the header is the did:key of the key, so the signing key is implied by the token.
        #expect(try DIDKey.keyID(for: key) == v["header"]!["kid"]!.str)
    }

    @Test(arguments: ["keys/p256.json", "keys/ed25519.json", "keys/p256-unlisted.json"])
    func testKeysImportAndSign(file: String) throws {
        let f = Fixtures.load(file)
        let key = try SigningKey(jwk: f["privateJwk"]!.object)
        #expect(JSONValue.object(key.publicKey.jwk) == f["publicJwk"]!)
        #expect(JSONValue.object(key.jwk) == f["privateJwk"]!)
        let data = Data("signature input".utf8)
        let signature = try key.sign(data)
        #expect(signature.count == 64)
        let pub = try VerificationKey(jwk: f["publicJwk"]!.object)
        #expect(pub.verify(signature, for: data))
        #expect(!pub.verify(signature, for: Data("other input".utf8)))
        #expect(kind(syncError { try SigningKey(jwk: f["publicJwk"]!.object) }) == "invalidArgument")
    }

    @Test func generatedKeysRoundTrip() throws {
        for key in [SigningKey.generateP256(), .generateEd25519(), try .generate(algorithm: "ES384")] {
            let again = try SigningKey(jwk: key.jwk)
            #expect(again.publicKey == key.publicKey)
            let sig = try again.sign(Data("x".utf8))
            #expect(key.publicKey.verify(sig, for: Data("x".utf8)))
        }
        var mismatched = SigningKey.generateP256().jwk
        mismatched["x"] = SigningKey.generateP256().jwk["x"]
        #expect(kind(syncError { try SigningKey(jwk: mismatched) }) == "invalidArgument")
        #expect(kind(syncError { try SigningKey.generate(algorithm: "RS256") }) == "invalidArgument")
    }

    private static func vector(_ file: String) -> (v: JSONValue, headers: HTTPHeaders, body: Data, description: StorageDescription) {
        let v = Fixtures.load("webhook/" + file)
        let description = try! StorageDescription.parse(Fixtures.load("webhook/storage-description.json"), base: url("https://storage.example/"))
        return (v, HTTPHeaders(v["headers"]!.object.map { ($0.key, $0.value.str) }), Data(v["body"]!.str.utf8), description)
    }

    @Test(arguments: Fixtures.strings("webhook/index.json", "vectors"))
    func webhookVector(file: String) async throws {
        let (v, headers, body, description) = Self.vector(file)
        let fetches = Counter()
        let now = Date(timeIntervalSince1970: TimeInterval(v["now"]!.intValue!))
        let verifier = WebhookVerifier(options: .init(storageDescriptionResolver: { u in
            _ = fetches.next()
            #expect(u.absoluteString == "https://storage.example/")
            return description
        }, now: { now }))
        let expected = v["expected"]!

        if let signatureBase = v["signatureBase"]?.stringValue {
            guard case .innerList(let covered)? = try StructuredFields.parseDictionary(headers.first("signature-input")!)["sig1"] else {
                Issue.record("sig1 is not an inner list")
                return
            }
            #expect(try WebhookVerifier.signatureBase(method: v["method"]!.str, url: url(v["url"]!.str), headers: headers, covered: covered)
                == signatureBase)
        }

        if expected["valid"]?.boolValue != true {
            let e = await error { try await verifier.verify(method: v["method"]!.str, url: url(v["url"]!.str), headers: headers, body: body) }
            #expect(kind(e) == "signatureVerification", "\(file): \(String(describing: e))")
            return
        }
        let verified = try await verifier.verify(method: v["method"]!.str, url: url(v["url"]!.str), headers: headers, body: body)
        #expect(verified.keyID == expected["keyid"]!.str)
        #expect(verified.storage.absoluteString == "https://storage.example/")
        let n = expected["notification"]!
        #expect(verified.notification.storage.absoluteString == n["storage"]!.str)
        let activities = n["activities"]!.array
        #expect(verified.notification.activities.count == activities.count)
        for (x, a) in zip(activities, verified.notification.activities) {
            #expect(a.types == x["types"]!.strings)
            #expect(a.object.id.absoluteString == x["objectId"]!.str)
            #expect(a.target?.absoluteString == x["target"]?.stringValue)
        }
        #expect(fetches.next() == 1)

        // The description is cached: a second delivery does not fetch it again.
        _ = try await verifier.verify(method: v["method"]!.str, url: url(v["url"]!.str), headers: headers, body: body)
        #expect(fetches.next() == 2)
    }

    @Test func webhookTrustedStoragesAreEnforcedEvenWhenEmpty() async throws {
        let (v, headers, body, description) = Self.vector("p256-valid.json")
        let now = Date(timeIntervalSince1970: TimeInterval(v["now"]!.intValue!))
        func make(_ trusted: [URL]?) -> WebhookVerifier {
            WebhookVerifier(options: .init(storageDescriptionResolver: { _ in description }, trustedStorages: trusted, now: { now }))
        }
        let inbox = url(v["url"]!.str)
        #expect(kind(await error { try await make([]).verify(method: "POST", url: inbox, headers: headers, body: body) }) == "signatureVerification")
        #expect(kind(await error { try await make([url("https://other.example/")]).verify(method: "POST", url: inbox, headers: headers, body: body) })
            == "signatureVerification")
        // Compared as URLs: case and the default port do not matter.
        let ok = try await make([url("HTTPS://Storage.Example:443/")]).verify(method: "POST", url: inbox, headers: headers, body: body)
        #expect(ok.storage.absoluteString == "https://storage.example/")
        _ = try await make(nil).verify(method: "POST", url: inbox, headers: headers, body: body)
    }

    @Test func webhookKeyRotationRefetchesOnce() async throws {
        let (v, headers, body, current) = Self.vector("p256-valid.json")
        // A stale description whose key-p256 is the unlisted key (as if the storage rotated keys since).
        var doc = Fixtures.load("webhook/storage-description.json").object
        var methods = doc["verificationMethod"]!.array
        var first = methods[0].object
        first["publicKeyJwk"] = Fixtures.load("keys/p256-unlisted.json")["publicJwk"]!
        methods[0] = .object(first)
        doc["verificationMethod"] = .array(methods)
        let stale = try StorageDescription.parse(.object(doc), base: url("https://storage.example/"))
        let fetches = Counter()
        let staleFirst = Counter()
        let now = Date(timeIntervalSince1970: TimeInterval(v["now"]!.intValue!))
        let verifier = WebhookVerifier(options: .init(storageDescriptionResolver: { _ in
            _ = fetches.next()
            return staleFirst.next() < 2 ? stale : current
        }, now: { now }))
        let inbox = url(v["url"]!.str)
        // The first fetch is stale and not cached yet: the failure is final.
        #expect(kind(await error { try await verifier.verify(method: "POST", url: inbox, headers: headers, body: body) }) == "signatureVerification")
        // A second stale fetch would fail too; the stale description is cached now, so verification refetches once.
        _ = staleFirst.next()
        _ = try await verifier.verify(method: "POST", url: inbox, headers: headers, body: body)
        #expect(fetches.next() == 2)
    }
}
