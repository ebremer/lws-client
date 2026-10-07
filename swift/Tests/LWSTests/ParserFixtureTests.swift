// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import LWS

/// The shared parser fixtures: Link, WWW-Authenticate, structured fields, JSON Patch / Pointer, type queries.
@Suite struct ParserFixtureTests {
    @Test(arguments: Fixtures.names("link-headers.json"))
    func linkHeaders(name: String) {
        let c = Fixtures.case("link-headers.json", name)
        let links = LinkHeader.parse(c["headers"]!.strings, base: url(c["base"]!.str))
        let expected = c["expected"]!.array
        #expect(links.count == expected.count)
        for (e, l) in zip(expected, links) {
            #expect(l.href.absoluteString == e["href"]!.str)
            #expect(l.rel == e["rel"]!.str)
            #expect(l.parameters == Dictionary(uniqueKeysWithValues: e["params"]!.object.map { ($0.key, $0.value.str) }))
        }
    }

    @Test func linkFormatEscapesAndRoundTrips() {
        let link = Link(href: url("https://example.org/c"), rel: "related").with(parameter: "title", "say \"hi\" \\ bye").with(parameter: "crossorigin", "")
        let formatted = LinkHeader.format(link)
        #expect(formatted == "<https://example.org/c>; rel=\"related\"; title=\"say \\\"hi\\\" \\\\ bye\"; crossorigin")
        let back = LinkHeader.parse(formatted, base: nil)
        #expect(back == [link])
        #expect(Link.type(ResourceType.container)!.headerValue == "<https://www.w3.org/ns/lws#Container>; rel=\"type\"")
        #expect(LinkHeader.format([Link(href: url("a"), rel: "up"), Link(href: url("b"), rel: "next")]) == "<a>; rel=\"up\", <b>; rel=\"next\"")
    }

    @Test(arguments: Fixtures.names("www-authenticate.json"))
    func wwwAuthenticateChallenges(name: String) {
        let c = Fixtures.case("www-authenticate.json", name)
        let challenges = WWWAuthenticate.parse(c["headers"]!.strings)
        let expected = c["expected"]!.array
        #expect(challenges.count == expected.count)
        for (e, ch) in zip(expected, challenges) {
            #expect(ch.isScheme(e["scheme"]!.str))
            #expect(ch.token68 == e["token68"]?.stringValue)
            #expect(ch.parameters == Dictionary(uniqueKeysWithValues: e["params"]!.object.map { ($0.key, $0.value.str) }))
        }
    }

    @Test func challengeAccessors() {
        let c = WWWAuthenticate.parse(#"Bearer as_uri="https://as.example", realm="https://s.example/", error="invalid_token", error_description="expired""#)
        #expect(c.count == 1)
        #expect(c[0].asURI == "https://as.example")
        #expect(c[0].realm == "https://s.example/")
        #expect(c[0].error == "invalid_token")
        #expect(c[0].errorDescription == "expired")
        #expect(WWWAuthenticate.parse("").isEmpty)
    }

    @Test(arguments: Fixtures.names("structured-fields.json"))
    func structuredFieldDictionaries(name: String) throws {
        let c = Fixtures.case("structured-fields.json", name)
        if c["error"]?.boolValue == true {
            #expect(throws: StructuredFieldError.self) { try StructuredFields.parseDictionary(c["input"]!.str) }
            return
        }
        let dict = try StructuredFields.parseDictionary(c["input"]!.str)
        let expected = c["expected"]!.object
        #expect(dict.keys == expected.keys)
        for e in expected {
            let member = dict[e.key]!
            if let items = e.value["innerList"] {
                guard case .innerList(let list) = member else {
                    Issue.record("\(e.key) is not an inner list")
                    continue
                }
                #expect(list.items.count == items.array.count)
                for (ei, item) in zip(items.array, list.items) {
                    expectBareItem(ei["item"]!, item.value)
                    expectParameters(ei["params"]!, item.parameters)
                }
            } else {
                guard case .item(let item) = member else {
                    Issue.record("\(e.key) is not an item")
                    continue
                }
                expectBareItem(e.value["item"]!, item.value)
            }
            expectParameters(e.value["params"]!, member.parameters)
        }
        for s in c["serialized"]?.object ?? JSONObject() {
            let serialized = try StructuredFields.serialize(dict[s.key]!)
            #expect(serialized == s.value.str)
        }
    }

    private func expectParameters(_ expected: JSONValue, _ actual: SFParameters) {
        #expect(actual.entries.map(\.key) == expected.object.keys)
        for p in expected.object { expectBareItem(p.value, actual[p.key]!) }
    }

    private func expectBareItem(_ expected: JSONValue, _ actual: SFBareItem) {
        let typed = expected.object.first!
        switch typed.key {
        case "string": #expect(actual == .string(typed.value.str))
        case "token": #expect(actual == .token(typed.value.str))
        case "integer": #expect(actual == .integer(typed.value.intValue!))
        case "decimal": #expect(actual == .decimal(typed.value.doubleValue!))
        case "boolean": #expect(actual == .boolean(typed.value.boolValue!))
        case "bytes": #expect(actual == .byteSequence(Data(base64Encoded: typed.value.str)!))
        default: Issue.record("unknown typed value \(typed.key)")
        }
    }

    @Test func structuredFieldSerialization() throws {
        let d = try StructuredFields.parseDictionary(#"a=?1, b=?0, c, d=tok/en, e=42, f=-3.5, g="str \"q\"";p=1;q, h=:AAEC:"#)
        #expect(try StructuredFields.serialize(d) == #"a, b=?0, c, d=tok/en, e=42, f=-3.5, g="str \"q\"";p=1;q, h=:AAEC:"#)
        #expect(try StructuredFields.serializeBareItem(.decimal(1)) == "1.0")
        #expect(try StructuredFields.serializeBareItem(.decimal(0.1235)) == "0.124")
        #expect(try StructuredFields.serializeBareItem(.date(1_700_000_000)) == "@1700000000")
        #expect(try StructuredFields.serializeBareItem(.displayString("fü%")) == #"%"f%c3%bc%25""#)
        #expect(try StructuredFields.parseItem(#"%"f%c3%bc%25""#).value == .displayString("fü%"))
        #expect(try StructuredFields.parseItem("@1700000000").value == .date(1_700_000_000))
        #expect(try StructuredFields.parseList("a, (b c);x=1").count == 2)
        #expect(throws: StructuredFieldError.self) { try StructuredFields.parseItem("1.2345") }
        #expect(throws: StructuredFieldError.self) { try StructuredFields.parseItem("1234567890123456") }
        #expect(throws: StructuredFieldError.self) { try StructuredFields.parseDictionary("a=:not base64!:") }
        #expect(throws: StructuredFieldError.self) { try StructuredFields.serializeBareItem(.string("ünicode")) }
    }

    @Test func jsonPointerEscapes() throws {
        let f = Fixtures.load("json-patch.json")
        for c in f["pointerEscapes"]!.array {
            #expect(JSONPointer.escape(c["segment"]!.str) == c["escaped"]!.str)
            #expect(JSONPointer.unescape(c["escaped"]!.str) == c["segment"]!.str)
        }
        for c in f["pointers"]!.array {
            #expect(JSONPointer.from(c["segments"]!.strings) == c["pointer"]!.str)
            #expect(try JSONPointer.parse(c["pointer"]!.str) == c["segments"]!.strings)
        }
        #expect(kind(syncError { try JSONPointer.parse("no-slash") }) == "invalidArgument")
    }

    @Test func jsonPatchSerialization() throws {
        let f = Fixtures.load("json-patch.json")
        let ops = f["patch"]!["operations"]!.array
        let patch = JSONPatch()
            .add(ops[0]["path"]!.str, ops[0]["value"]!)
            .remove(ops[1]["path"]!.str)
            .replace(ops[2]["path"]!.str, ops[2]["value"]!)
            .move(from: ops[3]["from"]!.str, to: ops[3]["path"]!.str)
            .copy(from: ops[4]["from"]!.str, to: ops[4]["path"]!.str)
            .test(ops[5]["path"]!.str, ops[5]["value"]!)
        #expect(try JSONValue(parsing: patch.description) == f["patch"]!["operations"]!)
        #expect(patch.operations.count == 6)
        #expect(JSONPatch().add("/n", nil).description == #"[{"op":"add","path":"/n","value":null}]"#)
        #expect(JSONPatch.mediaType == "application/json-patch+json")
    }

    @Test(arguments: Fixtures.names("type-queries.json"))
    func typeQueries(name: String) throws {
        let c = Fixtures.case("type-queries.json", name)
        func build() throws -> TypeQuery {
            var q = TypeQuery()
            for step in c["steps"]!.array {
                let key = step["key"]!.str
                q = step["allOf"] != nil ? try q.relation(key).allOf(step["allOf"]!.strings) : try q.relation(key).anyOf(step["anyOf"]!.strings)
            }
            return q
        }
        if c["error"]?.boolValue == true {
            #expect(kind(syncError(of: build)) == "invalidArgument")
            return
        }
        let query = try build()
        #expect(JSONValue.object(query.json) == c["json"]!, "\(query)")
        let rebuilt = try TypeQuery.from(json: c["json"]!)
        #expect(rebuilt.description == query.description)
    }

    @Test func typeQueryHelpers() throws {
        #expect(try TypeQuery().allOf("https://schema.org/Person").description == #"{"type":["https://schema.org/Person"]}"#)
        #expect(try TypeQuery.empty.anyOf("https://a.example/A", "https://b.example/B").description
            == #"{"type":[["https://a.example/A","https://b.example/B"]]}"#)
        #expect(TypeQuery.empty.description == "{}")
        #expect(try TypeQuery.empty.allOf("https://a.example/A").allOf("https://a.example/A").description == #"{"type":["https://a.example/A"]}"#)
        #expect(kind(syncError { try TypeQuery.empty.relation("@id") }) == "invalidArgument")
        #expect(kind(syncError { try TypeQuery.from(json: try JSONValue(parsing: #"{"type":[42]}"#)) }) == "invalidArgument")
        #expect(kind(syncError { try TypeQuery.from(json: try JSONValue(parsing: #"{"type":"x"}"#)) }) == "invalidArgument")
        #expect(!TypeQuery.isAbsoluteIRI("Person"))
        #expect(TypeQuery.isAbsoluteIRI("urn:x:y"))
    }

    @Test func problemDetailsFixture() throws {
        let f = Fixtures.load("responses/problem-details.json")
        let body = f["body"]!.serializedData()
        let headers = HTTPHeaders(f["headers"]!.object.map { ($0.key, $0.value.str) })
        let e = LWSError.from(HTTPError(status: Int(f["status"]!.intValue!), method: "DELETE", url: url("https://storage.example/alice/notes/"),
                                        headers: headers, body: body))
        let expected = f["expected"]!
        guard case .conflict(let h) = e else {
            Issue.record("not a conflict: \(e)")
            return
        }
        #expect(h.status == 409)
        let p = try #require(h.problem)
        #expect(p.type == expected["type"]!.str)
        #expect(p.title == expected["title"]!.str)
        #expect(p.detail == expected["detail"]!.str)
        #expect(p.instance == expected["instance"]!.str)
        #expect(p.status == 409)
        #expect(p.extensions["itemCount"] == 3)
        #expect(e.description.contains("Container not empty"))
        #expect(JSONValue.object(p.raw) == f["body"]!)
    }

    @Test func problemDetailsDetection() {
        #expect(ProblemDetails.parse(contentType: "text/plain", body: Data(#"{"title":"x"}"#.utf8)) == nil)
        #expect(ProblemDetails.parse(contentType: "application/json", body: Data(#"{"other":1}"#.utf8)) == nil)
        #expect(ProblemDetails.parse(contentType: "application/json", body: Data(#"{"title":"x"}"#.utf8)) != nil)
        #expect(ProblemDetails.parse(contentType: "application/problem+json; charset=utf-8", body: Data("{}".utf8)) != nil)
        #expect(ProblemDetails.parse(contentType: "application/problem+json", body: Data("not json".utf8)) == nil)
        #expect(ProblemDetails.parse(contentType: "application/problem+json", body: Data()) == nil)
    }

    @Test func jsonValueRoundTrips() throws {
        let text = #"{"b":1,"a":[true,false,null,1.5,-2,"x\"\\\/\né😀"],"c":{}}"#
        let v = try JSONValue(parsing: text)
        #expect(v["b"] == 1)
        #expect(v["a"]?[3] == 1.5)
        #expect(v["a"]?[5] == "x\"\\/\né😀")
        #expect(v.serialized() == #"{"b":1,"a":[true,false,null,1.5,-2,"x\"\\/\né😀"],"c":{}}"#)
        #expect(throws: JSONParseError.self) { try JSONValue(parsing: "{\"a\":1,}") }
        #expect(throws: JSONParseError.self) { try JSONValue(parsing: "[1] 2") }
        #expect(throws: JSONParseError.self) { try JSONValue(parsing: "\"\u{01}\"") }
        #expect(throws: JSONParseError.self) { try JSONValue(parsing: "01") }
        #expect(try JSONValue(parsing: "1e3") == .double(1000))
        #expect(try JSONValue(parsing: "9223372036854775808").doubleValue == 9_223_372_036_854_775_808)
        #expect(JSONValue.double(31).serialized() == "31")
        #expect(JSONValue.double(0.1).serialized() == "0.1")
    }
}
