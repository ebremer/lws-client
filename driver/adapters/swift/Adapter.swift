// SPDX-License-Identifier: MIT
import Foundation
import LWS

/// The operations of `driver/PROTOCOL.md`, run with lws-client for Swift. The adapter is a thin wrapper: it calls the
/// library's operations with the library's options and reports the library's results and errors, without retrying
/// or fixing anything up.
@MainActor
final class Adapter {
    static let `protocol` = "lws-driver/1"
    static let language = "swift"
    static let library = "lws-client-swift/" + LWSClient.version

    typealias Operation = @MainActor (JSONObject) async throws -> JSONValue

    /// The client every operation uses; `configure` replaces it.
    private var client = LWSClient()

    /// The operations, in the protocol's order.
    private(set) var operations: [(name: String, run: Operation)] = []

    init() {
        operations = [
            ("configure", { [unowned self] in try configure($0) }),
            ("discover_storage", { [unowned self] a in Results.storage(try await client.discoverStorage(try Args.requiredURL(a, "url"))) }),
            ("get_storage_description", { [unowned self] a in Results.storage(try await client.getStorageDescription(try Args.requiredURL(a, "url"))) }),
            ("head", { [unowned self] a in Results.metadata(try await client.head(try Args.requiredURL(a, "url"))) }),
            ("read", { [unowned self] in try await read($0) }),
            ("read_container", { [unowned self] a in Results.page(try await client.readContainer(try Args.requiredURL(a, "url"))) }),
            ("list_container", { [unowned self] a in try await items(client.listContainer(try Args.requiredURL(a, "url")), try Args.limit(a)) }),
            ("create", { [unowned self] in try await create($0) }),
            ("create_container", { [unowned self] a in
                let parent = try Args.requiredURL(a, "parent")
                return Results.created(try await client.createContainer(in: parent, options: CreateOptions(slug: try Args.optionalString(a, "slug"))))
            }),
            ("update", { [unowned self] in try await update($0) }),
            ("patch", { [unowned self] a in
                let url = try Args.requiredURL(a, "url")
                return Results.update(try await client.patch(url, patch: try Args.patch(Args.get(a, "patch")), options: try ifMatch(a)))
            }),
            ("delete", { [unowned self] a in
                let url = try Args.requiredURL(a, "url")
                try await client.delete(url, options: DeleteOptions(ifMatch: try Args.optionalString(a, "ifMatch"),
                                                                    recursive: try Args.optionalBoolean(a, "recursive") ?? false))
                return [:]
            }),
            ("linkset_url", { [unowned self] a in ["linkset": .string(try await client.linksetURL(try Args.requiredURL(a, "url")).absoluteString)] }),
            ("read_linkset", { [unowned self] a in Results.linkset(try await client.readLinkset(try Args.requiredURL(a, "url"))) }),
            ("update_linkset", { [unowned self] a in
                let url = try Args.requiredURL(a, "linksetUrl")
                let linkset = try Args.document("linkset") { try Linkset.parse(.object(try Args.requiredObject(a, "linkset"))) }
                return Results.update(try await client.updateLinkset(url, linkset: linkset, options: try ifMatch(a)))
            }),
            ("patch_linkset", { [unowned self] a in
                let url = try Args.requiredURL(a, "linksetUrl")
                return Results.update(try await client.patchLinkset(url, patch: try Args.patch(Args.get(a, "patch")), options: try ifMatch(a)))
            }),
            ("subscribe", { [unowned self] in try await subscribe($0) }),
            ("list_subscriptions", { [unowned self] a in
                try await items(client.listSubscriptions(try Args.requiredURL(a, "serviceUrl")), try Args.limit(a))
            }),
            ("get_subscription", { [unowned self] a in Results.subscription(try await client.getSubscription(try Args.requiredURL(a, "url"))) }),
            ("unsubscribe", { [unowned self] a in
                try await client.unsubscribe(try Args.requiredURL(a, "url"))
                return [:]
            }),
            ("verify_notification", { [unowned self] in try await verifyNotification($0) }),
            ("request_access", { [unowned self] a in
                let service = try Args.requiredURL(a, "serviceUrl")
                let request = try Args.document("request") { try AccessRequest.parse(.object(try Args.requiredObject(a, "request"))) }
                return ["location": .string(try await client.requestAccess(service, request: request).absoluteString)]
            }),
            ("get_access_request", { [unowned self] a in document(try await client.getAccessRequest(try Args.requiredURL(a, "url"))) }),
            ("list_access_requests", { [unowned self] a in
                try await items(client.listAccessRequests(try Args.requiredURL(a, "serviceUrl")), try Args.limit(a))
            }),
            ("cancel_access_request", { [unowned self] a in
                try await client.cancelAccessRequest(try Args.requiredURL(a, "url"))
                return [:]
            }),
            ("grant_access", { [unowned self] a in
                let service = try Args.requiredURL(a, "serviceUrl")
                let grant = try Args.document("grant") { try AccessGrant.parse(.object(try Args.requiredObject(a, "grant"))) }
                return ["location": .string(try await client.grantAccess(service, grant: grant).absoluteString)]
            }),
            ("get_access_grant", { [unowned self] a in document(try await client.getAccessGrant(try Args.requiredURL(a, "url"))) }),
            ("list_access_grants", { [unowned self] a in
                try await items(client.listAccessGrants(try Args.requiredURL(a, "serviceUrl")), try Args.limit(a))
            }),
            ("revoke_access_grant", { [unowned self] a in
                try await client.revokeAccessGrant(try Args.requiredURL(a, "url"))
                return [:]
            }),
            ("read_type_index", { [unowned self] a in Results.typeIndex(try await client.readTypeIndex(try Args.requiredURL(a, "url"))) }),
            ("list_types", { [unowned self] a in
                let (types, truncated) = try await take(client.listTypes(try Args.requiredURL(a, "serviceUrl")), try Args.limit(a))
                return ["types": Results.strings(types), "truncated": .bool(truncated)]
            }),
            ("search_types", { [unowned self] a in
                let service = try Args.requiredURL(a, "serviceUrl")
                return Results.page(try await client.searchTypes(service, query: try Args.query(Args.get(a, "query"))))
            }),
            ("search_all", { [unowned self] a in
                let service = try Args.requiredURL(a, "serviceUrl")
                let query = try Args.query(Args.get(a, "query"))
                return try await items(client.searchAll(service, query: query), try Args.limit(a))
            }),
            ("accepted_query_formats", { [unowned self] a in
                ["formats": Results.strings(try await client.acceptedQueryFormats(try Args.requiredURL(a, "serviceUrl")))]
            }),
            ("shutdown", { _ in [:] }),
        ]
    }

    func operation(_ name: String) -> Operation? {
        operations.first { $0.name == name }?.run
    }

    // MARK: - configure

    private func configure(_ args: JSONObject) throws -> JSONValue {
        let authArg = Args.get(args, "auth")
        if let authArg, authArg.objectValue == nil { throw AdapterError.invalid("argument 'auth' must be an object") }
        let auth = authArg?.objectValue ?? ["type": "none"]
        let allowInsecureHttp = try Args.optionalBoolean(args, "allowInsecureHttp")
        let userAgent = try Args.optionalString(args, "userAgent")
        let timeoutSeconds = (try? Args.optionalNonNegativeInteger(args, "timeoutSeconds")) ?? 0
        if timeoutSeconds == 0, Args.get(args, "timeoutSeconds") != nil {
            throw AdapterError.invalid("argument 'timeoutSeconds' must be a positive integer")
        }
        var headers = HTTPHeaders()
        if let h = try Args.optionalObject(args, "headers") {
            for header in h {
                guard let v = header.value.stringValue else { throw AdapterError.invalid("header '\(header.key)' must be a string") }
                headers.set(header.key, v)
            }
        }

        var result: JSONObject = ["library": .string(Self.library)]
        let timeout: TimeInterval? = Args.get(args, "timeoutSeconds") == nil ? nil : TimeInterval(timeoutSeconds)
        func tokenExchange(_ credentials: any CredentialProvider) -> TokenExchangeAuthenticator {
            TokenExchangeAuthenticator(credentials: credentials, options: TokenExchangeOptions(
                allowInsecureHttp: allowInsecureHttp ?? false, timeout: timeout ?? 30, userAgent: userAgent ?? LWSClient.defaultUserAgent))
        }

        let authenticator: (any Authenticator)?
        let type = try Args.requiredString(auth, "type")
        switch type {
        case "none":
            authenticator = nil
        case "bearer":
            authenticator = BearerTokenAuthenticator(token: try Args.requiredString(auth, "token"), realm: try Args.optionalURL(auth, "realm"))
        case "openid":
            authenticator = tokenExchange(OpenIDCredentials(idToken: try Args.requiredString(auth, "idToken")))
        case "selfSigned":
            let agent = try Args.iri(try Args.requiredString(auth, "agent"), "agent")
            let jwk = try Args.requiredObject(auth, "privateJwk")
            guard let kid = try Args.optionalString(auth, "kid") ?? jwk["kid"]?.stringValue else {
                throw AdapterError.invalid("selfSigned needs 'kid', or a 'kid' in the private JWK")
            }
            let key: SigningKey
            do {
                key = try SigningKey(jwk: jwk)
            } catch LWSError.invalidArgument(let m) {
                throw AdapterError.invalid("argument 'privateJwk' is not a usable private key: \(m)")
            }
            authenticator = tokenExchange(SelfSignedCredentials.forAgent(agent, key: key, keyID: kid))
            result["agent"] = .string(agent)
            result["kid"] = .string(kid)
        case "didKey":
            let algorithm = try Args.optionalString(auth, "algorithm") ?? "ES256"
            let key: SigningKey
            switch algorithm {
            case "ES256": key = .generateP256()
            case "EdDSA": key = .generateEd25519()
            default: throw AdapterError.invalid("unknown algorithm '\(algorithm)'")
            }
            let credentials = try SelfSignedCredentials.didKey(key)
            authenticator = tokenExchange(credentials)
            result["agent"] = .string(credentials.agent)
            Results.put(&result, "kid", credentials.keyID)
        default:
            throw AdapterError.invalid("unknown auth type '\(type)'")
        }

        var options = LWSClientOptions(authenticator: authenticator, userAgent: userAgent ?? LWSClient.defaultUserAgent, defaultHeaders: headers)
        if let timeout { options.timeout = timeout }
        client = LWSClient(options: options)
        return .object(result)
    }

    // MARK: - Resources

    private func read(_ args: JSONObject) async throws -> JSONValue {
        let url = try Args.requiredURL(args, "url")
        let start = try Args.optionalNonNegativeInteger(args, "rangeStart")
        let end = try Args.optionalNonNegativeInteger(args, "rangeEnd")
        var range: ByteRange?
        switch (start, end) {
        case (nil, nil): range = nil
        case (nil, _): throw AdapterError.invalid("rangeEnd needs rangeStart")
        case (let s?, nil): range = .from(s)
        case (let s?, let e?):
            guard e >= s else { throw AdapterError.invalid("rangeEnd must not be before rangeStart") }
            range = .bytes(s...e)
        }
        let options = ReadOptions(accept: try Args.optionalString(args, "accept"), range: range,
                                  ifNoneMatch: try Args.optionalString(args, "ifNoneMatch"), prefer: try Args.optionalString(args, "prefer"))
        let resource = try await client.read(url, options: options)
        var result: JSONObject = ["metadata": Results.metadata(resource.metadata), "notModified": .bool(resource.notModified)]
        Results.put(&result, "contentRange", resource.contentRange)
        result["body"] = Results.body(resource)
        return .object(result)
    }

    private func create(_ args: JSONObject) async throws -> JSONValue {
        let container = try Args.requiredURL(args, "container")
        let body = try Args.body(Args.get(args, "body"), try Args.optionalString(args, "contentType"))
        let types = try Args.optionalArray(args, "types").map { try Args.strings($0, "types") } ?? []
        var links: [Link] = []
        for link in try Args.optionalArray(args, "links") ?? [] {
            guard let o = link.objectValue else { throw AdapterError.invalid("argument 'links' must be a list of {href, rel} objects") }
            let href = try Args.requiredString(o, "href")
            let rel = try Args.requiredString(o, "rel")
            guard let u = URL(string: href) else { throw AdapterError.invalid("argument 'links' has an invalid href: \(href)") }
            links.append(Link(href: u, rel: rel))
        }
        let options = CreateOptions(slug: try Args.optionalString(args, "slug"), links: links, types: types)
        return Results.created(try await client.create(in: container, body: body.bytes, contentType: body.contentType, options: options))
    }

    private func update(_ args: JSONObject) async throws -> JSONValue {
        let url = try Args.requiredURL(args, "url")
        guard Args.get(args, "body") != nil else { throw AdapterError.invalid("missing argument 'body'") }
        let body = try Args.body(Args.get(args, "body"), try Args.optionalString(args, "contentType"))
        let options = UpdateOptions(ifMatch: try Args.optionalString(args, "ifMatch"), ifNoneMatch: try Args.optionalString(args, "ifNoneMatch"))
        return Results.update(try await client.update(url, body: body.bytes, contentType: body.contentType, options: options))
    }

    /// Update options carrying only the optional `ifMatch`.
    private func ifMatch(_ args: JSONObject) throws -> UpdateOptions {
        UpdateOptions(ifMatch: try Args.optionalString(args, "ifMatch"))
    }

    // MARK: - Notifications

    private func subscribe(_ args: JSONObject) async throws -> JSONValue {
        let service = try Args.requiredURL(args, "serviceUrl")
        let topics = try Args.urls(try Args.requiredArray(args, "topics"), "topics")
        let inbox = try Args.requiredURL(args, "inbox")
        let expires = try Args.optionalString(args, "expires").map { try Args.dateTime($0, "expires") }
        let request: WebhookSubscriptionRequest
        do {
            request = try WebhookSubscriptionRequest(topics: topics, inbox: inbox, expires: expires)
        } catch LWSError.invalidArgument(let m) {
            throw AdapterError.invalid(m)
        }
        return Results.subscription(try await client.subscribe(service, request: request))
    }

    private func verifyNotification(_ args: JSONObject) async throws -> JSONValue {
        let method = try Args.requiredString(args, "method")
        let url = try Args.requiredURL(args, "url")
        var headers = HTTPHeaders()
        for h in try Args.requiredObject(args, "headers") {
            switch h.value {
            case .string(let v): headers.add(h.key, v)
            case .array(let a): for v in try Args.strings(a, "headers." + h.key) { headers.add(h.key, v) }
            default: throw AdapterError.invalid("header '\(h.key)' must be a list of values")
            }
        }
        let body = try Args.base64(try Args.requiredString(args, "bodyBase64"), "bodyBase64")
        let trusted = try Args.optionalArray(args, "trustedStorages").map { try Args.urls($0, "trustedStorages") }
        let verifier = WebhookVerifier(options: WebhookVerifierOptions(client: client, trustedStorages: trusted))
        return Results.verified(try await verifier.verify(method: method, url: url, headers: headers, body: body))
    }

    // MARK: - Access

    /// The document as the library received it (its `raw`), else as the library serializes it.
    private func document(_ doc: some AccessDocument) -> JSONValue {
        ["document": .object(doc.raw ?? doc.json)]
    }

    // MARK: - Lazy sequences

    private func items(_ sequence: PagedSequence<ContainedResource>, _ limit: Int64) async throws -> JSONValue {
        let (items, truncated) = try await take(sequence, limit)
        return ["items": .array(items.map(Results.item)), "truncated": .bool(truncated)]
    }

    /// Pulls at most `limit` + 1 elements from a lazy sequence, returns the first `limit`, and says whether there was
    /// one more.
    private func take<T: Sendable>(_ sequence: PagedSequence<T>, _ limit: Int64) async throws -> ([T], Bool) {
        var items: [T] = []
        for try await item in sequence {
            if items.count == limit { return (items, true) }
            items.append(item)
        }
        return (items, false)
    }
}
