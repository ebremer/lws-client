// SPDX-License-Identifier: MIT
import Foundation

extension LWSClient {
    private static let acceptDescription = MediaType.lwsCID + ", " + MediaType.ldJSON + ";q=0.9, " + MediaType.json + ";q=0.8"
    private static let acceptLinkset = MediaType.linksetJSON + ", " + MediaType.json + ";q=0.5"

    // MARK: - Discovery

    /// Finds the storage a resource belongs to (its `rel="https://www.w3.org/ns/lws#storage"` link, from a `HEAD`,
    /// or a `GET` when `HEAD` is answered 405 or 501) and retrieves the storage description.
    /// - Throws: ``LWSError/protocolError(_:)`` when the response has no storage link or the description is invalid.
    public func discoverStorage(_ resourceURL: URL, options: RequestOptions = RequestOptions()) async throws -> StorageDescription {
        let url = try URLs.requireHTTP(resourceURL, "resourceURL")
        var r = try await call("HEAD", url, nil, HTTPHeaders(), options)
        if r.status == 405 || r.status == 501 { r = try await call("GET", url, nil, HTTPHeaders(), options) }
        // A 401 SHOULD carry the storage link too, so that anonymous discovery works.
        guard let storage = r.metadata.storage, r.status / 100 == 2 || r.status == 401 else {
            try r.check()
            throw LWSError.protocolError("The response for \(url.absoluteString) has no storage link (rel=\"\(LinkRelation.storage)\")")
        }
        return try await getStorageDescription(storage, options: options)
    }

    /// Retrieves and parses a storage description (`application/lws+cid`).
    /// - Throws: ``LWSError/protocolError(_:)`` when the document is not a storage description.
    public func getStorageDescription(_ storageURL: URL, options: RequestOptions = RequestOptions()) async throws -> StorageDescription {
        let url = try URLs.requireHTTP(storageURL, "storageURL")
        let r = try await call("GET", url, nil, ["Accept": Self.acceptDescription], options)
        try r.check()
        if let ct = r.headers.first("content-type"), !HeaderLists.isJSON(ct), HeaderLists.essence(ct) != MediaType.lwsCID {
            throw LWSError.protocolError("The storage description has the unexpected media type \(ct)")
        }
        return try StorageDescription.parse(LWSJSON.parse(r.body, "Storage description"), base: r.url)
    }

    // MARK: - Reading

    /// Retrieves a resource's metadata (`HEAD`).
    public func head(_ url: URL, options: RequestOptions = RequestOptions()) async throws -> ResourceMetadata {
        let r = try await call("HEAD", try URLs.requireHTTP(url, "url"), nil, HTTPHeaders(), options)
        try r.check()
        return r.metadata
    }

    /// Reads a resource (`GET`). A conditional read answered `304` returns a result whose ``Resource/notModified``
    /// is true instead of throwing; `206` is a normal result.
    public func read(_ url: URL, options: ReadOptions = ReadOptions()) async throws -> Resource {
        let r = try await call("GET", try URLs.requireHTTP(url, "url"), nil, Self.readHeaders(options), options)
        return try Self.resource(r)
    }

    /// Reads one page of a container listing (`Accept: application/lws+json`); also takes opaque page URLs.
    /// - Throws: ``LWSError/protocolError(_:)`` when the response is not an LWS container representation.
    public func readContainer(_ url: URL, options: RequestOptions = RequestOptions()) async throws -> ContainerPage {
        let u = try URLs.requireHTTP(url, "url")
        let r = try await call("GET", u, nil, ["Accept": MediaType.lwsJSON], options)
        let page = try Self.page(r)
        guard page.isContainer else {
            throw LWSError.protocolError("\(r.url.absoluteString) is not a container (type [\(page.types.joined(separator: ", "))])")
        }
        return page
    }

    /// Every member of a container, fetched lazily page by page (following `rel="next"`).
    public func listContainer(_ url: URL, options: RequestOptions = RequestOptions()) -> PagedSequence<ContainedResource> {
        PagedSequence(first: url,
                      load: { let p = try await self.readContainer(url, options: options); return (p.items, p.next) },
                      fetch: { let p = try await self.readContainer($0, options: options); return (p.items, p.next) })
    }

    // MARK: - Creating

    /// Creates a data resource in a container (`POST`); the server assigns its URL (``CreateResult/location``).
    /// - Throws: ``LWSError/protocolError(_:)`` when the response has no `Location`.
    public func create(in containerURL: URL, body: Data, contentType: String, options: CreateOptions = CreateOptions()) async throws
        -> CreateResult
    {
        let u = try URLs.requireHTTP(containerURL, "containerURL")
        var headers = Self.createHeaders(options, containerType: nil)
        headers.set("Content-Type", contentType)
        return try Self.created(try await call("POST", u, body, headers, options))
    }

    /// Creates a text data resource (UTF-8).
    public func createText(in containerURL: URL, text: String, contentType: String = "text/plain",
                           options: CreateOptions = CreateOptions()) async throws -> CreateResult
    {
        try await create(in: containerURL, body: Data(text.utf8), contentType: contentType, options: options)
    }

    /// Creates a JSON data resource (`application/json`).
    public func createJSON(in containerURL: URL, json: JSONValue, options: CreateOptions = CreateOptions()) async throws -> CreateResult {
        try await create(in: containerURL, body: json.serializedData(), contentType: MediaType.json, options: options)
    }

    /// Creates a JSON data resource (`application/json`) from any `Encodable` value.
    public func createJSON<T: Encodable>(in containerURL: URL, value: T, encoder: JSONEncoder = JSONEncoder(),
                                         options: CreateOptions = CreateOptions()) async throws -> CreateResult
    {
        let data: Data
        do {
            data = try encoder.encode(value)
        } catch {
            throw LWSError.invalidArgument("Cannot encode \(T.self) as JSON: \(error)")
        }
        return try await create(in: containerURL, body: data, contentType: MediaType.json, options: options)
    }

    /// Creates a sub-container (`POST` with `Link: <https://www.w3.org/ns/lws#Container>; rel="type"`, empty body).
    public func createContainer(in parentURL: URL, options: CreateOptions = CreateOptions()) async throws -> CreateResult {
        let u = try URLs.requireHTTP(parentURL, "parentURL")
        return try Self.created(try await call("POST", u, Data(), Self.createHeaders(options, containerType: ResourceType.container), options))
    }

    // MARK: - Updating and deleting

    /// Replaces a resource's content (`PUT`); use ``UpdateOptions/ifMatch`` to avoid lost updates.
    public func update(_ url: URL, body: Data, contentType: String, options: UpdateOptions = UpdateOptions()) async throws -> UpdateResult {
        try await updateCore("PUT", url, body, contentType, options)
    }

    /// Applies a JSON Patch (`application/json-patch+json`, the LWS baseline patch format).
    public func patch(_ url: URL, patch: JSONPatch, options: UpdateOptions = UpdateOptions()) async throws -> UpdateResult {
        try await updateCore("PATCH", url, patch.data, MediaType.jsonPatch, options)
    }

    /// Applies a patch in any format the server advertises in `Accept-Patch` (e.g. `application/sparql-update`).
    public func patch(_ url: URL, body: Data, contentType: String, options: UpdateOptions = UpdateOptions()) async throws -> UpdateResult {
        try await updateCore("PATCH", url, body, contentType, options)
    }

    private func updateCore(_ method: String, _ url: URL, _ body: Data, _ contentType: String, _ options: UpdateOptions) async throws
        -> UpdateResult
    {
        let u = try URLs.requireHTTP(url, "url")
        let r = try await call(method, u, body, Self.updateHeaders(options, contentType), options)
        try r.check()
        return UpdateResult(status: r.status, metadata: r.metadata, body: r.body)
    }

    /// Deletes a resource; a non-empty container needs ``DeleteOptions/recursive`` (else ``LWSError/conflict(_:)``).
    public func delete(_ url: URL, options: DeleteOptions = DeleteOptions()) async throws {
        var headers = HTTPHeaders()
        headers.set("If-Match", options.ifMatch)
        if options.recursive { headers.set("Depth", "infinity") }
        let r = try await call("DELETE", try URLs.requireHTTP(url, "url"), nil, headers, options)
        try r.check()
    }

    // MARK: - Metadata (linksets)

    /// The linkset resource URL of a resource (`HEAD`, `rel="linkset"`).
    /// - Throws: ``LWSError/protocolError(_:)`` when the resource has no linkset link.
    public func linksetURL(_ resourceURL: URL, options: RequestOptions = RequestOptions()) async throws -> URL {
        let m = try await head(resourceURL, options: options)
        guard let linkset = m.linkset else { throw LWSError.protocolError("\(m.url.absoluteString) has no linkset link") }
        return linkset
    }

    /// Discovers and reads a resource's linkset (`application/linkset+json`).
    public func readLinkset(_ resourceURL: URL, options: RequestOptions = RequestOptions()) async throws -> LinksetDocument {
        try await readLinksetResource(try await linksetURL(resourceURL, options: options), options: options)
    }

    /// Reads a linkset resource at a known URL.
    public func readLinksetResource(_ linksetURL: URL, options: RequestOptions = RequestOptions()) async throws -> LinksetDocument {
        let r = try await call("GET", try URLs.requireHTTP(linksetURL, "linksetURL"), nil, ["Accept": Self.acceptLinkset], options)
        try r.check()
        return LinksetDocument(url: r.url, linkset: try Linkset.parse(LWSJSON.parse(r.body, "Linkset")), metadata: r.metadata)
    }

    /// Replaces a linkset (`PUT`; only when the server allows it, else ``LWSError/methodNotAllowed(_:)``).
    public func updateLinkset(_ linksetURL: URL, linkset: Linkset, options: UpdateOptions = UpdateOptions()) async throws -> UpdateResult {
        try await updateCore("PUT", linksetURL, JSONValue.object(linkset.json).serializedData(), MediaType.linksetJSON, options)
    }

    /// Patches a linkset with JSON Patch; ``JSONPointer`` escapes relation keys that are URIs.
    public func patchLinkset(_ linksetURL: URL, patch: JSONPatch, options: UpdateOptions = UpdateOptions()) async throws -> UpdateResult {
        try await self.patch(linksetURL, patch: patch, options: options)
    }

    // MARK: - Notifications

    /// Creates a webhook subscription at a notification service endpoint.
    /// - Throws: ``LWSError/protocolError(_:)`` when the response has neither a subscription URL nor a `Location`.
    public func subscribe(_ serviceURL: URL, request: WebhookSubscriptionRequest, options: RequestOptions = RequestOptions()) async throws
        -> Subscription
    {
        let u = try URLs.requireHTTP(serviceURL, "serviceURL")
        let r = try await call("POST", u, JSONValue.object(request.json).serializedData(), Self.jsonHeaders, options)
        try r.check()
        let location = r.headers.first("location").flatMap { URLs.resolve($0, against: r.url) }
        if r.body.allSatisfy({ $0 == 0x20 || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }) {
            guard let location else { throw LWSError.protocolError("The subscription response has neither a body nor a Location") }
            return try Subscription.parse(["type": .string(SubscriptionType.webhook)], base: r.url, location: location)
        }
        return try Subscription.parse(LWSJSON.parse(r.body, "Subscription"), base: r.url, location: location)
    }

    /// Creates a webhook subscription at a storage's notification service, checking that it offers webhooks.
    /// - Throws: ``LWSError/protocolError(_:)`` when the service does not support `WebhookSubscription`.
    public func subscribe(_ service: Service, request: WebhookSubscriptionRequest, options: RequestOptions = RequestOptions()) async throws
        -> Subscription
    {
        if !service.subscriptionTypes.isEmpty, !service.subscriptionTypes.contains(SubscriptionType.webhook) {
            throw LWSError.protocolError("The notification service \(service.serviceEndpoint.absoluteString) does not support \(SubscriptionType.webhook)")
        }
        return try await subscribe(service.serviceEndpoint, request: request, options: options)
    }

    /// The subscriber's subscriptions: the container listing of the notification service.
    public func listSubscriptions(_ serviceURL: URL, options: RequestOptions = RequestOptions()) -> PagedSequence<ContainedResource> {
        listContainer(serviceURL, options: options)
    }

    /// Retrieves a subscription's current state.
    public func getSubscription(_ url: URL, options: RequestOptions = RequestOptions()) async throws -> Subscription {
        let r = try await call("GET", try URLs.requireHTTP(url, "url"), nil, ["Accept": MediaType.lwsJSON], options)
        try r.check()
        return try Subscription.parse(LWSJSON.parse(r.body, "Subscription"), base: r.url, location: r.url)
    }

    /// Cancels a subscription (`DELETE`).
    public func unsubscribe(_ url: URL, options: RequestOptions = RequestOptions()) async throws {
        try await delete(url, options: Self.deleteOptions(options))
    }

    // MARK: - Access requests and grants

    /// Submits an access request; returns its URL (`Location`).
    public func requestAccess(_ serviceURL: URL, request: AccessRequest, options: RequestOptions = RequestOptions()) async throws -> URL {
        try await postForLocation(serviceURL, request.json, options)
    }

    /// The access requests: the container listing of the service.
    public func listAccessRequests(_ serviceURL: URL, options: RequestOptions = RequestOptions()) -> PagedSequence<ContainedResource> {
        listContainer(serviceURL, options: options)
    }

    /// Retrieves an access request (its ``AccessRequest/raw`` is the document as sent).
    public func getAccessRequest(_ url: URL, options: RequestOptions = RequestOptions()) async throws -> AccessRequest {
        try AccessRequest.parse(try await getJSON(url, options))
    }

    /// Cancels (deletes) an access request.
    public func cancelAccessRequest(_ url: URL, options: RequestOptions = RequestOptions()) async throws {
        try await delete(url, options: Self.deleteOptions(options))
    }

    /// Creates an access grant (as storage controller); returns its URL (`Location`).
    public func grantAccess(_ serviceURL: URL, grant: AccessGrant, options: RequestOptions = RequestOptions()) async throws -> URL {
        try await postForLocation(serviceURL, grant.json, options)
    }

    /// The access grants: the container listing of the service.
    public func listAccessGrants(_ serviceURL: URL, options: RequestOptions = RequestOptions()) -> PagedSequence<ContainedResource> {
        listContainer(serviceURL, options: options)
    }

    /// Retrieves an access grant (its ``AccessGrant/raw`` is the document as sent).
    public func getAccessGrant(_ url: URL, options: RequestOptions = RequestOptions()) async throws -> AccessGrant {
        try AccessGrant.parse(try await getJSON(url, options))
    }

    /// Revokes (deletes) an access grant.
    public func revokeAccessGrant(_ url: URL, options: RequestOptions = RequestOptions()) async throws {
        try await delete(url, options: Self.deleteOptions(options))
    }

    // MARK: - Type index and type search

    /// Reads a type index page (the service endpoint, or an opaque page URL).
    public func readTypeIndex(_ url: URL, options: RequestOptions = RequestOptions()) async throws -> TypeIndexPage {
        let r = try await call("GET", try URLs.requireHTTP(url, "url"), nil, ["Accept": MediaType.lwsJSON], options)
        try r.check()
        try Self.requireLWSJSON(r)
        return try TypeIndexPage.parse(LWSJSON.parse(r.body, "Type index"), metadata: r.metadata)
    }

    /// Every type IRI of a type index, fetched lazily page by page.
    public func listTypes(_ serviceURL: URL, options: RequestOptions = RequestOptions()) -> PagedSequence<String> {
        PagedSequence(first: serviceURL,
                      load: { let p = try await self.readTypeIndex(serviceURL, options: options); return (p.types, p.next) },
                      fetch: { let p = try await self.readTypeIndex($0, options: options); return (p.types, p.next) })
    }

    /// Runs a type search (HTTP `QUERY`, RFC 10008, with an `application/lws-query+json` filter) and returns the
    /// first page. The page's ``ContainerPage/id`` is the page URL when the body has no `id`.
    public func searchTypes(_ serviceURL: URL, query: TypeQuery, options: RequestOptions = RequestOptions()) async throws -> ContainerPage {
        let u = try URLs.requireHTTP(serviceURL, "serviceURL")
        let headers: HTTPHeaders = ["Content-Type": MediaType.lwsQueryJSON, "Accept": MediaType.lwsJSON]
        return try Self.page(try await call("QUERY", u, query.data, headers, options))
    }

    /// Every search result: the first page by `QUERY`, further pages by `GET` of the opaque `next` links.
    public func searchAll(_ serviceURL: URL, query: TypeQuery, options: RequestOptions = RequestOptions()) -> PagedSequence<ContainedResource> {
        PagedSequence(first: serviceURL,
                      load: { let p = try await self.searchTypes(serviceURL, query: query, options: options); return (p.items, p.next) },
                      fetch: { let p = try await self.readSearchPage($0, options); return (p.items, p.next) })
    }

    private func readSearchPage(_ url: URL, _ options: RequestOptions) async throws -> ContainerPage {
        try Self.page(try await call("GET", try URLs.requireHTTP(url, "url"), nil, ["Accept": MediaType.lwsJSON], options))
    }

    /// The query formats a search service accepts (`OPTIONS`, `Accept-Query`).
    public func acceptedQueryFormats(_ serviceURL: URL, options: RequestOptions = RequestOptions()) async throws -> [String] {
        let r = try await call("OPTIONS", try URLs.requireHTTP(serviceURL, "serviceURL"), nil, HTTPHeaders(), options)
        try r.check()
        return HeaderLists.split(r.headers.all("accept-query")).map(HeaderLists.unquote)
    }

    // MARK: - Low-level access

    /// Sends any request through the client's pipeline (authentication, redirects). An error status throws the
    /// matching ``LWSError``; `304` yields a not-modified result.
    public func request(_ method: String, _ url: URL, body: Data? = nil, contentType: String? = nil,
                        options: RequestOptions = RequestOptions()) async throws -> Resource
    {
        var headers = HTTPHeaders()
        headers.set("Content-Type", contentType)
        return try Self.resource(try await call(method, try URLs.requireHTTP(url, "url"), body, headers, options))
    }

    // MARK: - Internals of the operations

    private func call(_ method: String, _ url: URL, _ body: Data?, _ headers: HTTPHeaders, _ options: some OperationOptions) async throws
        -> Answer
    {
        var h = headers
        for name in options.headers.names { h.remove(name) }
        for f in options.headers { h.add(f.name, f.value) }
        return try await send(Call(method: method, url: url, body: body, headers: h, timeout: options.timeout))
    }

    private static let jsonHeaders: HTTPHeaders = ["Content-Type": MediaType.lwsJSON, "Accept": MediaType.lwsJSON]

    private static func resource(_ r: Answer) throws -> Resource {
        if r.status == 304 { return Resource(metadata: r.metadata, body: Data(), notModified: true) }
        try r.check()
        return Resource(metadata: r.metadata, body: r.body, notModified: false)
    }

    private static func page(_ r: Answer) throws -> ContainerPage {
        try r.check()
        try requireLWSJSON(r)
        return try ContainerPage.parse(LWSJSON.parse(r.body, "Container representation"), metadata: r.metadata)
    }

    private static func requireLWSJSON(_ r: Answer) throws {
        guard let essence = HeaderLists.essence(r.headers.first("content-type")) else { return }
        guard essence == MediaType.lwsJSON || essence == MediaType.ldJSON || essence == MediaType.json else {
            throw LWSError.protocolError("Unexpected media type \(essence) for an LWS JSON representation at \(r.url.absoluteString)")
        }
    }

    private static func created(_ r: Answer) throws -> CreateResult {
        try r.check()
        guard let location = r.headers.first("location") else {
            throw LWSError.protocolError("The create response (HTTP \(r.status)) from \(r.url.absoluteString) has no Location header")
        }
        guard let resolved = URLs.resolve(location, against: r.url) else { throw LWSError.protocolError("Invalid Location header: \(location)") }
        return CreateResult(location: resolved, metadata: r.metadata, body: r.body)
    }

    private func postForLocation(_ serviceURL: URL, _ document: JSONObject, _ options: RequestOptions) async throws -> URL {
        let u = try URLs.requireHTTP(serviceURL, "serviceURL")
        return try Self.created(try await call("POST", u, JSONValue.object(document).serializedData(), Self.jsonHeaders, options)).location
    }

    private func getJSON(_ url: URL, _ options: RequestOptions) async throws -> JSONValue {
        let r = try await call("GET", try URLs.requireHTTP(url, "url"), nil, ["Accept": MediaType.lwsJSON], options)
        try r.check()
        return try LWSJSON.parse(r.body, "Response of \(r.url.absoluteString)")
    }

    private static func deleteOptions(_ o: RequestOptions) -> DeleteOptions {
        DeleteOptions(headers: o.headers, timeout: o.timeout)
    }

    private static func readHeaders(_ o: ReadOptions) -> HTTPHeaders {
        var h = HTTPHeaders()
        h.set("Accept", o.accept)
        h.set("Range", o.range?.headerValue)
        h.set("If-None-Match", o.ifNoneMatch)
        h.set("If-Modified-Since", o.ifModifiedSince.map(Dates.formatHTTPDate))
        h.set("Prefer", o.prefer)
        return h
    }

    private static func createHeaders(_ o: CreateOptions, containerType: String?) -> HTTPHeaders {
        var h = HTTPHeaders()
        if let containerType { h.add("Link", LinkHeader.format(href: containerType, rel: LinkRelation.type)) }
        for t in o.types { h.add("Link", LinkHeader.format(href: t, rel: LinkRelation.type)) }
        for l in o.links { h.add("Link", LinkHeader.format(l)) }
        if let slug = o.slug { h.set(Slug.headerName, Slug.encode(slug)) }
        return h
    }

    private static func updateHeaders(_ o: UpdateOptions, _ contentType: String) -> HTTPHeaders {
        var h: HTTPHeaders = ["Content-Type": contentType]
        h.set("If-Match", o.ifMatch)
        h.set("If-None-Match", o.ifNoneMatch)
        for l in o.links { h.add("Link", LinkHeader.format(l)) }
        if o.setLinkset { h.set("Prefer", Prefer.setLinkset) }
        return h
    }
}
