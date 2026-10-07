// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import LWS

/// The shared response fixtures (`conformance/fixtures/responses`) and the models they parse into.
@Suite struct ModelFixtureTests {
    private func headers(_ json: JSONValue) -> HTTPHeaders {
        HTTPHeaders(json.object.flatMap { m in
            m.value.arrayValue.map { $0.map { (m.key, $0.str) } } ?? [(m.key, m.value.str)]
        })
    }

    private func iso(_ s: String) -> Date {
        let f = ISO8601DateFormatter()
        f.formatOptions = s.contains(".") ? [.withInternetDateTime, .withFractionalSeconds] : [.withInternetDateTime]
        return f.date(from: s)!
    }

    @Test func containerPageFixture() throws {
        let f = Fixtures.load("responses/container-page.json")
        let metadata = ResourceMetadata(url: url(f["url"]!.str), status: Int(f["status"]!.intValue!), headers: headers(f["headers"]!))
        let page = try ContainerPage.parse(f["body"]!, metadata: metadata)
        let e = f["expected"]!
        #expect(page.id.absoluteString == e["id"]!.str)
        #expect(page.isContainer)
        #expect(page.totalItems == e["totalItems"]!.intValue)
        #expect(page.etag == e["etag"]!.str)
        #expect(page.metadata.linkset?.absoluteString == e["linkset"]!.str)
        #expect(page.metadata.parent?.absoluteString == e["parent"]!.str)
        #expect(page.metadata.storage?.absoluteString == e["storage"]!.str)
        #expect(page.first?.absoluteString == e["first"]!.str)
        #expect(page.next?.absoluteString == e["next"]!.str)
        #expect(page.prev == nil)
        #expect(page.last?.absoluteString == e["last"]!.str)
        #expect(page.metadata.isContainer)
        let items = e["items"]!.array
        #expect(page.items.count == items.count)
        for (x, item) in zip(items, page.items) {
            #expect(item.id.absoluteString == x["id"]!.str)
            #expect(item.isContainer == x["isContainer"]!.boolValue)
            #expect(item.isDataResource == x["isDataResource"]!.boolValue)
            #expect(item.format == x["format"]!.stringValue)
            #expect(item.size == x["size"]!.intValue)
            #expect(item.types == x["types"]!.strings)
            if let modified = x["modified"]?.stringValue {
                #expect(item.modified == iso(modified))
            } else {
                #expect(item.modified == nil)
            }
            if let raw = x["modifiedRaw"]?.stringValue { #expect(item.modifiedRaw == raw) }
            if let t = x["hasType"]?.stringValue { #expect(item.hasType(t)) }
        }
    }

    @Test func containerPageWithoutIdUsesThePageURL() throws {
        let metadata = ResourceMetadata(url: url("https://example.org/types/search?cursor=1"), status: 200, headers: HTTPHeaders())
        let page = try ContainerPage.parse(try JSONValue(parsing: #"{"type":"ContainerPage","items":[]}"#), metadata: metadata)
        #expect(page.id.absoluteString == "https://example.org/types/search?cursor=1")
        #expect(!page.isContainer)
        for bad in [#"{"items":{}}"#, #"{"items":[{"type":"x"}]}"#, "[]"] {
            #expect(kind(syncError { try ContainerPage.parse(try JSONValue(parsing: bad), metadata: metadata) }) == "protocolError")
        }
    }

    @Test func storageDescriptionFixture() throws {
        let f = Fixtures.load("responses/storage-description.json")
        let s = try StorageDescription.parse(f["body"]!, base: url(f["url"]!.str))
        let e = f["expected"]!
        #expect(s.id.absoluteString == e["id"]!.str)
        #expect(s.types == e["types"]!.strings)
        #expect(try s.storageRoot().absoluteString == e["storageRoot"]!.str)
        #expect(s.notificationService?.serviceEndpoint.absoluteString == e["notificationService"]!.str)
        #expect(s.notificationService?.subscriptionTypes == e["notificationSubscriptionTypes"]!.strings)
        #expect(s.typeIndexService?.serviceEndpoint.absoluteString == e["typeIndexService"]!.str)
        #expect(s.typeSearchService?.serviceEndpoint.absoluteString == e["typeSearchService"]!.str)
        #expect(s.accessRequestService?.serviceEndpoint.absoluteString == e["accessRequestService"]!.str)
        #expect(s.accessGrantService?.serviceEndpoint.absoluteString == e["accessGrantService"]!.str)
        #expect(s.services.count == Int(e["serviceCount"]!.intValue!))
        #expect(s.capabilities.flatMap(\.types) == e["capabilityTypes"]!.strings)
        let custom = e["customService"]!
        let sharing = try #require(s.service(custom["type"]!.str))
        #expect(sharing.id?.absoluteString == custom["id"]!.str)
        #expect(sharing.serviceEndpoint.absoluteString == custom["serviceEndpoint"]!.str)
        #expect(s.accessGrantService?.conformsTo == [Vocabulary.accessProfile])
        #expect(s.capability("https://feature.example/PatchSupport")?.property("format") != nil)
        #expect(s.services(ServiceType.storageRoot).count == 1)

        let invalid = f["invalid"]!
        #expect(kind(syncError { try StorageDescription.parse(invalid["notStorage"]!, base: url(f["url"]!.str)) }) == "protocolError")
        let noRoot = try StorageDescription.parse(invalid["noRoot"]!, base: url(f["url"]!.str))
        #expect(kind(syncError { try noRoot.storageRoot() }) == "protocolError")
    }

    @Test func webhookStorageDescriptionKeys() throws {
        let s = try StorageDescription.parse(Fixtures.load("webhook/storage-description.json"), base: url("https://storage.example/"))
        #expect(s.verificationMethods.count == 3)
        let p256 = try #require(s.verificationMethod("https://storage.example/#key-p256"))
        let ed = try #require(s.verificationMethod("https://storage.example/#key-ed25519"))
        #expect(ed.id == "#key-ed25519")
        #expect(s.verificationMethod("key-ed25519")?.id == ed.id)
        #expect(s.verificationMethod("#key-ed25519")?.id == ed.id)
        #expect(s.isAuthenticationMethod(p256))
        #expect(s.isAuthenticationMethod(ed))
        #expect(!s.isAuthenticationMethod(try #require(s.verificationMethod("#key-unlisted"))))
        #expect(s.verificationMethod("#nope") == nil)
        #expect(p256.type == "JsonWebKey")
        #expect(p256.controller == "https://storage.example/")
        #expect(p256.publicKeyJwk?.string("kty") == "EC")
    }

    @Test func linksetFixture() throws {
        let f = Fixtures.load("responses/linkset.json")
        let metadata = ResourceMetadata(url: url(f["url"]!.str), status: 200, headers: headers(f["headers"]!))
        let ls = try Linkset.parse(f["body"]!)
        let doc = LinksetDocument(url: metadata.url, linkset: ls, metadata: metadata)
        let e = f["expected"]!
        let anchor = e["anchor"]!.str
        #expect(doc.url.absoluteString == e["url"]!.str)
        #expect(doc.etag == e["etag"]!.str)
        #expect(doc.allow == e["allow"]!.strings)
        #expect(doc.acceptPatch == e["acceptPatch"]!.strings)
        #expect(doc.supportsPut)
        #expect(ls.contexts.count == Int(e["contexts"]!.intValue!))
        #expect(ls.contexts[0].anchor == anchor)
        #expect(ls.links.count == Int(e["linkCount"]!.intValue!))
        for t in e["targets"]!.object {
            #expect(ls.targets(t.key).map(\.href) == t.value.strings)
            #expect(ls.targets(anchor: anchor, rel: t.key).map(\.href) == t.value.strings)
        }
        let add = e["afterAdd"]!
        let op = add["operation"]!
        let added = ls.adding(anchor: op["anchor"]!.str, rel: op["rel"]!.str, href: op["href"]!.str)
        #expect(added.targets("license").map(\.href) == add["licenseTargets"]!.strings)
        #expect(ls.targets("license").count == 1)
        #expect(JSONValue.object(ls.json) == f["body"]!, "round trip")
        #expect(JSONValue.object(try Linkset.parse(ls.description).json) == f["body"]!)

        let describedBy = try #require(ls.links.first { $0.rel == "describedby" })
        #expect(describedBy.href.absoluteString == "https://storage.example/schemas/personal-info.json")
        #expect(describedBy.type == "application/schema+json")
        #expect(describedBy.anchor == anchor)
        #expect(ls.targets("https://example.org/rel/reviewer")[0].attribute("title") == "Bob")

        let removed = ls.removing(anchor: anchor, rel: "https://example.org/rel/reviewer", href: "https://id.example/bob")
        #expect(removed.targets("https://example.org/rel/reviewer").map(\.href) == ["https://id.example/carol"])
        #expect(ls.removing(anchor: anchor, rel: "license").targets("license").isEmpty)
        let fresh = Linkset.empty.adding(anchor: "https://a.example/x", rel: "describedby", href: "https://a.example/shape",
                                         attributes: ["type": "text/turtle"])
        #expect(fresh.description == #"{"linkset":[{"anchor":"https://a.example/x","describedby":[{"href":"https://a.example/shape","type":"text/turtle"}]}]}"#)
        #expect(kind(syncError { try Linkset.parse(#"{"linkset":"not a list"}"#) }) == "protocolError")
        #expect(kind(syncError { try Linkset.parse(#"{"linkset":[1]}"#) }) == "protocolError")
    }

    @Test func notificationFixture() throws {
        let f = Fixtures.load("responses/notification.json")
        expectNotification(f["singleExpected"]!, try Notification.parse(f["single"]!))
        expectNotification(f["batchExpected"]!, try Notification.parse(f["batch"]!.serializedData()))
        #expect(kind(syncError { try Notification.parse(f["invalid"]!) }) == "protocolError")
        #expect(kind(syncError { try Notification.parse(Data(#"{"type":"Notification","storage":"https://s.example/"}"#.utf8)) }) == "protocolError")
        #expect(kind(syncError { try Notification.parse(Data("not json".utf8)) }) == "protocolError")
    }

    private func expectNotification(_ expected: JSONValue, _ n: LWS.Notification) {
        #expect(n.storage.absoluteString == expected["storage"]!.str)
        let activities = expected["activities"]!.array
        #expect(n.activities.count == activities.count)
        for (x, a) in zip(activities, n.activities) {
            #expect(a.id == x["id"]!.str)
            #expect(a.types == x["types"]!.strings)
            #expect(a.object.id.absoluteString == x["objectId"]!.str)
            if let t = x["objectTypes"] { #expect(a.object.types == t.strings) }
            if let origin = x["origin"]?.stringValue { #expect(a.origin?.absoluteString == origin) }
            if let actor = x["actor"]?.stringValue { #expect(a.actor?.absoluteString == actor) }
            if let target = x["target"]?.stringValue { #expect(a.target?.absoluteString == target) }
            if let published = x["published"]?.stringValue {
                #expect(a.publishedRaw == published)
                #expect(a.published == iso(published))
            }
            if x["isCreate"] != nil { #expect(a.isCreate) }
            if x["isUpdate"] != nil { #expect(a.isUpdate) }
            if x["isDelete"] != nil { #expect(a.isDelete) }
            #expect(a.object.isDataResource)
        }
    }

    @Test func subscriptionFixture() throws {
        let f = Fixtures.load("responses/subscription.json")
        let input = f["input"]!
        let request = try WebhookSubscriptionRequest(topics: input["topics"]!.strings.map(url), inbox: url(input["inbox"]!.str),
                                                     expires: iso(input["expires"]!.str))
        #expect(JSONValue.object(request.json) == f["expectedRequestBody"]!, "\(request.json)")
        let s = try Subscription.parse(f["response"]!["body"]!, base: url("https://notification.example/"), location: nil)
        let e = f["expected"]!
        #expect(s.type == e["type"]!.str)
        #expect(s.url.absoluteString == e["subscription"]!.str)
        #expect(s.expiresRaw == e["expires"]!.str)
        #expect(s.expires == iso(e["expires"]!.str))
        #expect(kind(syncError { try WebhookSubscriptionRequest(topics: [], inbox: url("https://r.example/")) }) == "invalidArgument")
        let fallback = try Subscription.parse(["type": "WebhookSubscription"], base: nil, location: url("https://n.example/s/1"))
        #expect(fallback.url.absoluteString == "https://n.example/s/1")
        #expect(kind(syncError { try Subscription.parse([:], base: nil, location: nil) }) == "protocolError")
    }

    @Test func typeIndexAndSearchFixtures() throws {
        let f = Fixtures.load("responses/type-index.json")
        let index = f["typeIndex"]!
        let page = try TypeIndexPage.parse(index["body"]!, metadata: ResourceMetadata(url: url(index["url"]!.str), status: 200, headers: headers(index["headers"]!)))
        let ie = index["expected"]!
        #expect(page.totalItems == ie["totalItems"]!.intValue)
        #expect(page.types == ie["types"]!.strings)
        #expect(page.next?.absoluteString == ie["next"]!.str)
        #expect(page.first?.absoluteString == "https://example.org/types/index?page=1")
        #expect(page.last?.absoluteString == "https://example.org/types/index?page=4")

        let search = f["search"]!
        let results = try ContainerPage.parse(search["body"]!,
                                              metadata: ResourceMetadata(url: url(search["url"]!.str), status: 200, headers: headers(search["headers"]!)))
        let se = search["expected"]!
        #expect(results.totalItems == se["totalItems"]!.intValue)
        #expect(results.items.map(\.id.absoluteString) == se["ids"]!.strings)
        #expect(results.next?.absoluteString == se["next"]!.str)
        #expect(results.id.absoluteString == search["url"]!.str)
        #expect(results.hasType("ContainerPage"))
        #expect(results.items[0].hasType("https://schema.org/Person"))
    }

    @Test func accessFixture() throws {
        let f = Fixtures.load("responses/access.json")
        let request = try AccessRequest.parse(f["request"]!)
        #expect(request.storage.absoluteString == "https://storage.example/")
        #expect(request.inbox?.absoluteString == "https://id.example/agent/inbox/")
        #expect(request.access.count == 1)
        let policy = request.access[0]
        #expect(policy.actions == ["read", "create"])
        #expect(policy.assignee == "https://id.example/agent")
        #expect(policy.target?.type == "StorageResource")
        #expect(policy.target?.values == ["https://storage.example/root/projects/"])
        #expect(policy.constraints.count == 2)
        #expect(policy.constraints[0].leftOperand == "purpose")
        #expect(policy.constraints[1].operator == "lteq")
        #expect(request.raw.map { JSONValue.object($0) } == f["request"]!)
        #expect(JSONValue.object(request.json) == f["request"]!)

        let grant = try AccessGrant.parse(f["grant"]!)
        #expect(grant.access[0].constraints[0].rightOperand.strings == ["image/jpeg", "image/png"])
        #expect(JSONValue.object(grant.json) == f["grant"]!)
        #expect(kind(syncError { try AccessGrant.parse(f["request"]!) }) == "protocolError")
        #expect(kind(syncError { try AccessRequest.parse(f["grant"]!) }) == "protocolError")

        // The builder expectation: the same request built from parts.
        let built = try AccessRequest(
            storage: url("https://storage.example/"),
            access: [AccessPolicy(actions: ["read", "create"], assignee: "https://id.example/agent",
                                  target: .storageResources(url("https://storage.example/root/projects/")),
                                  constraints: [.purpose(url("https://purpose.example/collaboration")), .notAfter(iso("2026-06-09T10:00:00Z"))])],
            inbox: url("https://id.example/agent/inbox/"))
        #expect(JSONValue.object(built.json) == f["request"]!, "\(built.json)")
        #expect(built.raw == nil)

        let approving = AccessGrant.approving(built)
        #expect(approving.types == ["AccessGrant"])
        #expect(approving.access == built.access)

        // Builders validate the required fields.
        #expect(kind(syncError { try AccessPolicy(actions: [], assignee: "https://id.example/agent") }) == "invalidArgument")
        #expect(kind(syncError { try AccessPolicy(actions: ["read"], assignee: "agent") }) == "invalidArgument")
        #expect(kind(syncError { try AccessRequest(storage: url("https://s.example/"), access: []) }) == "invalidArgument")
        #expect(kind(syncError { try AccessTarget(type: "Container", values: []) }) == "invalidArgument")
        #expect(kind(syncError { try AccessRequest.parse(try JSONValue(parsing: #"{"type":"AccessRequest","storage":"https://s.example/","access":[]}"#)) })
            == "protocolError")
        #expect(kind(syncError { try AccessRequest.parse(try JSONValue(parsing: #"{"type":"AccessRequest","access":[{}]}"#)) }) == "protocolError")
    }

    @Test func constraintFactories() throws {
        func text(_ c: Constraint) -> String { "\(c.leftOperand) \(c.operator) \(c.rightOperand.serialized())" }
        #expect(text(.purpose(url("https://p.example/x"))) == #"purpose eq "https://p.example/x""#)
        #expect(text(.purposeAnyOf([url("https://p.example/a"), url("https://p.example/b")]))
            == #"purpose isAnyOf ["https://p.example/a","https://p.example/b"]"#)
        #expect(text(.client(url("https://app.example/id"))) == #"client eq "https://app.example/id""#)
        #expect(text(.format("image/png")) == #"format eq "image/png""#)
        #expect(text(.formatAnyOf(["image/png", "image/jpeg"])) == #"format isAnyOf ["image/png","image/jpeg"]"#)
        #expect(text(.type(url("https://schema.org/Person"))) == #"type eq "https://schema.org/Person""#)
        #expect(text(.typeAnyOf([url("https://schema.org/Person")])) == #"type isAnyOf ["https://schema.org/Person"]"#)
        #expect(text(.notBefore(iso("2026-01-02T03:04:05Z"))) == #"dateTime gteq "2026-01-02T03:04:05Z""#)
        #expect(text(.notAfter(iso("2026-01-02T04:04:05.500+01:00"))) == #"dateTime lteq "2026-01-02T03:04:05.5Z""#)
        #expect(try AccessTarget.storageResources(url("https://s.example/a")).type == "StorageResource")
        #expect(try AccessTarget.containers(url("https://s.example/a/")).type == "Container")
        #expect(try AccessTarget.dataResources(url("https://s.example/a")).type == "DataResource")
    }

    @Test func oauthFixture() throws {
        let f = Fixtures.load("responses/oauth.json")
        let md = try AuthorizationServerMetadata.parse(f["metadata"]!, base: url("https://authorization.example/.well-known/lws-configuration"))
        #expect(md.issuer == "https://authorization.example")
        #expect(md.tokenEndpoint.absoluteString == "https://authorization.example/token")
        #expect(md.jwksURI?.absoluteString == "https://authorization.example/jwks")
        #expect(md.supportsSubjectTokenType(TokenType.jwt))
        #expect(md.supportsSubjectTokenType(TokenType.idToken))
        #expect(!md.supportsSubjectTokenType(TokenType.saml2))
        #expect(md.grantTypesSupported == [Vocabulary.grantTypeTokenExchange])
        #expect(md.subjectIdentifierTypesSupported == ["did:web", "did:key", "https"])

        for c in f["metadataUrls"]!.array {
            #expect(AuthorizationServerMetadata.metadataURL(issuer: url(c["issuer"]!.str)).absoluteString == c["url"]!.str)
        }

        let now = Date(timeIntervalSince1970: 1_735_000_000)
        let t = try AccessToken.fromTokenResponse(f["tokenResponse"]!["body"]!.object, now: now)
        #expect(t.expiresAt == now.addingTimeInterval(TimeInterval(f["tokenResponse"]!["expectedExpiresIn"]!.intValue!)))
        let noExpiry = try AccessToken.fromTokenResponse(f["tokenResponseNoExpiry"]!["body"]!.object, now: now)
        #expect(noExpiry.expiresAt == Date(timeIntervalSince1970: TimeInterval(f["tokenResponseNoExpiry"]!["expectedExp"]!.intValue!)))
        let opaque = try AccessToken.fromTokenResponse(["access_token": "opaque", "token_type": "Bearer"], now: now)
        #expect(opaque.expiresAt == now.addingTimeInterval(AccessToken.defaultLifetime))
        #expect(kind(syncError { try AccessToken.fromTokenResponse(["access_token": "x", "token_type": "DPoP"], now: now) }) == "authentication")
        #expect(kind(syncError { try AccessToken.fromTokenResponse(["token_type": "Bearer"], now: now) }) == "authentication")
        #expect(t.isValid(at: now, margin: 30))
        #expect(!t.isValid(at: now.addingTimeInterval(3580), margin: 30))

        for c in f["realmChecks"]!.array {
            #expect(URLs.contains(realm: url(c["realm"]!.str), url(c["url"]!.str)) == c["contained"]!.boolValue, "\(c)")
        }
    }

    @Test func everyFixtureFileIsCovered() throws {
        let vectors = Fixtures.load("webhook/index.json")["vectors"]!.strings
        let covered = [
            "did-key.json", "json-patch.json", "jwt.json", "link-headers.json", "structured-fields.json", "type-queries.json",
            "www-authenticate.json", "keys/ed25519.json", "keys/p256.json", "keys/p256-unlisted.json",
            "responses/access.json", "responses/container-page.json", "responses/linkset.json", "responses/notification.json",
            "responses/oauth.json", "responses/problem-details.json", "responses/storage-description.json", "responses/subscription.json",
            "responses/type-index.json", "webhook/index.json", "webhook/storage-description.json",
        ] + vectors.map { "webhook/" + $0 }
        let root = Fixtures.directory.standardizedFileURL.path
        var all: [String] = []
        let e = FileManager.default.enumerator(atPath: root)!
        while let p = e.nextObject() as? String {
            if p.hasSuffix(".json") { all.append(p) }
        }
        #expect(covered.sorted() == all.sorted())
        #expect(vectors.count == 13)
    }
}
