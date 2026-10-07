// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.http.Link
import com.ebremer.lws.kotlin.http.LinkHeader
import com.ebremer.lws.kotlin.http.SfBareItem
import com.ebremer.lws.kotlin.http.SfBoolean
import com.ebremer.lws.kotlin.http.SfBytes
import com.ebremer.lws.kotlin.http.SfDate
import com.ebremer.lws.kotlin.http.SfDecimal
import com.ebremer.lws.kotlin.http.SfDisplayString
import com.ebremer.lws.kotlin.http.SfInnerList
import com.ebremer.lws.kotlin.http.SfInteger
import com.ebremer.lws.kotlin.http.SfItem
import com.ebremer.lws.kotlin.http.SfMember
import com.ebremer.lws.kotlin.http.SfString
import com.ebremer.lws.kotlin.http.SfToken
import com.ebremer.lws.kotlin.http.Slug
import com.ebremer.lws.kotlin.http.StructuredFieldException
import com.ebremer.lws.kotlin.http.StructuredFields
import com.ebremer.lws.kotlin.http.WwwAuthenticate
import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import com.ebremer.lws.kotlin.json.JsonPatch
import com.ebremer.lws.kotlin.json.JsonPointer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.math.BigDecimal
import java.net.URI
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The shared fixtures for Link, WWW-Authenticate, structured fields, JSON Patch and TypeQuery. */
class ParserFixtureTest {

    @TestFactory
    fun linkHeaderFixture(): List<DynamicTest> = Fixtures.cases("link-headers.json") { case ->
        val links = LinkHeader.parse(case.strings("headers"), URI(case.str("base")))
        val got = links.map { mapOf("href" to it.href.toString(), "rel" to it.rel, "params" to it.params) }
        val expected = case.arr("expected").map { e ->
            val o = e.jsonObject
            mapOf("href" to o.str("href"), "rel" to o.str("rel"), "params" to o.obj("params").mapValues { it.value.str })
        }
        assertEquals(expected, got)
    }

    @Test
    fun linkSerializationRoundTrip() {
        val links = listOf(
            Link(URI("https://example.org/a"), "describedby", mapOf("type" to "text/turtle", "title" to "say \"hi\"")),
            Link.typeLink(URI("https://www.w3.org/ns/lws#Container")),
            Link(URI("https://example.org/e"), "alternate", mapOf("crossorigin" to "")),
        )
        val header = LinkHeader.formatAll(links)
        assertTrue(header.startsWith("<https://example.org/a>; rel=\"describedby\"; type=\"text/turtle\""))
        val parsed = LinkHeader.parse(header, URI("https://example.org/"))
        assertEquals(links, parsed)
        assertEquals("text/turtle", parsed[0].type)
        assertEquals("say \"hi\"", parsed[0].title)
    }

    @Test
    fun linkTitleStarAndHelpers() {
        val link = LinkHeader.parse("<https://example.org/h>; rel=related; title*=UTF-8''n%C3%A4me; anchor=\"#x\"").single()
        assertEquals("UTF-8''n%C3%A4me", link.params["title*"])
        assertEquals("näme", link.title)
        assertEquals("#x", link.anchor)
        assertNull(LinkHeader.decodeExtValue("bogus"))
        assertEquals("é", LinkHeader.decodeExtValue("iso-8859-1'fr'%E9"))
        val all = LinkHeader.parse(listOf("<a>; rel=\"next prev UP\"", "<https://x.example/r>; rel=\"https://Ext.example/Rel\""), URI("https://s.example/d/"))
        assertEquals(listOf("next", "prev", "up", "https://Ext.example/Rel"), all.map { it.rel })
        assertEquals(URI("https://s.example/d/a"), Link.first(all, "UP")?.href)
        assertTrue(all[3].hasRel("https://Ext.example/Rel"))
        assertFalse(all[3].hasRel("https://ext.example/rel"))
        assertEquals(2, Link.all(all + all[0], "next").size)
    }

    @TestFactory
    fun wwwAuthenticateFixture(): List<DynamicTest> = Fixtures.cases("www-authenticate.json") { case ->
        val challenges = WwwAuthenticate.parse(case.strings("headers"))
        val expected = case.arr("expected")
        assertEquals(expected.size, challenges.size)
        expected.forEachIndexed { i, e ->
            val exp = e.jsonObject
            assertTrue(challenges[i].isScheme(exp.str("scheme")))
            assertEquals(exp.obj("params").mapValues { it.value.str }, challenges[i].params)
            assertEquals(exp.strOrNull("token68"), challenges[i].token68)
        }
    }

    @Test
    fun challengeAccessors() {
        val ch = WwwAuthenticate.parse("Bearer as_uri=\"https://as.example\", realm=\"https://s.example/\", error=\"invalid_token\", error_description=\"expired\"").single()
        assertTrue(ch.isScheme("bearer"))
        assertEquals(listOf("https://as.example", "https://s.example/", "invalid_token", "expired"), listOf(ch.asUri, ch.realm, ch.error, ch.errorDescription))
        assertEquals("https://as.example", ch.param("AS_URI"))
    }

    private fun bare(v: SfBareItem): JsonObject = JsonObject(
        when (v) {
            is SfBoolean -> mapOf("boolean" to JsonPrimitive(v.value))
            is SfInteger -> mapOf("integer" to JsonPrimitive(v.value))
            is SfDecimal -> mapOf("decimal" to JsonPrimitive(v.value.toDouble()))
            is SfString -> mapOf("string" to JsonPrimitive(v.value))
            is SfToken -> mapOf("token" to JsonPrimitive(v.value))
            is SfBytes -> mapOf("bytes" to JsonPrimitive(Base64.getEncoder().encodeToString(v.bytes)))
            is SfDate -> mapOf("date" to JsonPrimitive(v.seconds))
            is SfDisplayString -> mapOf("displayString" to JsonPrimitive(v.value))
        },
    )

    private fun member(m: SfMember): JsonObject {
        val params = JsonObject(m.params.mapValues { bare(it.value) })
        return when (m) {
            is SfInnerList -> JsonObject(mapOf("innerList" to JsonArray(m.items.map(::member)), "params" to params))
            is SfItem -> JsonObject(mapOf("item" to bare(m.value), "params" to params))
        }
    }

    /** Compares JSON values with numbers as numbers (`-3.5` and `-3.50` alike). */
    private fun normalize(e: JsonElement): Any? = when (e) {
        is JsonObject -> e.mapValues { normalize(it.value) }
        is JsonArray -> e.map(::normalize)
        JsonNull -> null
        is JsonPrimitive -> if (e.isString) e.content else e.content.toBigDecimalOrNull()?.stripTrailingZeros() ?: e.content
    }

    @TestFactory
    fun structuredFieldsFixture(): List<DynamicTest> = Fixtures.cases("structured-fields.json") { case ->
        if (case.flag("error")) {
            assertFailsWith<StructuredFieldException> { StructuredFields.parseDictionary(case.str("input")) }
            return@cases
        }
        val parsed = StructuredFields.parseDictionary(case.str("input"))
        val expected = case.obj("expected")
        assertEquals(normalize(expected), normalize(JsonObject(parsed.mapValues { member(it.value) })))
        assertEquals(expected.keys.toList(), parsed.keys.toList())
        (case["serialized"] as? JsonObject)?.forEach { (key, text) ->
            assertEquals(text.str, StructuredFields.serializeMember(parsed.getValue(key)))
        }
        // The canonical serialization parses back to the same structure.
        assertEquals(parsed, StructuredFields.parseDictionary(StructuredFields.serializeDictionary(parsed)))
    }

    @Test
    fun structuredFieldListsItemsAndErrors() {
        assertEquals(
            listOf(SfItem(SfString("a")), SfItem(SfToken("tok")), SfInnerList(listOf(SfItem(SfInteger(1)), SfItem(SfInteger(2))), mapOf("p" to SfBoolean(true)))),
            StructuredFields.parseList("\"a\", tok, (1 2);p"),
        )
        assertEquals("2.5", StructuredFields.serializeBareItem(SfDecimal(BigDecimal("2.5"))))
        assertEquals("1.0", StructuredFields.serializeBareItem(SfDecimal(BigDecimal("1"))))
        assertEquals("0.124", StructuredFields.serializeBareItem(SfDecimal(BigDecimal("0.1235"))))
        assertEquals("@1659578233", StructuredFields.serializeBareItem(SfDate(1659578233)))
        assertEquals("(\"@method\");created=1", StructuredFields.serializeInnerList(SfInnerList(listOf(SfItem(SfString("@method"))), mapOf("created" to SfInteger(1)))))
        assertEquals(mapOf("d" to SfItem(SfDate(1659578233))), StructuredFields.parseDictionary("d=@1659578233"))
        val display = StructuredFields.parseDictionary("s=%\"f%c3%bc%c3%bc\"")["s"] as SfItem
        assertEquals(SfDisplayString("füü"), display.value)
        assertEquals("%\"f%c3%bc%c3%bc\"", StructuredFields.serializeBareItem(SfDisplayString("füü")))
        assertEquals(SfItem(SfBoolean(true), mapOf("a" to SfInteger(1))), StructuredFields.parseItem(" ?1;a=1 "))
        for (bad in listOf("a=1,", "a=(1 2", "A=1", "a=\"\\x\"", "a=1.2345", "a=:not base64:", "a=?2", "a=1 b=2")) {
            assertFailsWith<StructuredFieldException>(bad) { StructuredFields.parseDictionary(bad) }
        }
        assertFailsWith<StructuredFieldException> { StructuredFields.serializeBareItem(SfString("caf\u00e9")) }
    }

    @Test
    fun jsonPointerFixture() {
        val f = Fixtures.load("json-patch.json")
        for (c in f.arr("pointerEscapes").map { it.jsonObject }) {
            assertEquals(c.str("escaped"), JsonPointer.escape(c.str("segment")))
            assertEquals(c.str("segment"), JsonPointer.unescape(c.str("escaped")))
        }
        for (c in f.arr("pointers").map { it.jsonObject }) {
            assertEquals(c.str("pointer"), JsonPointer.fromSegments(c.strings("segments")))
            assertEquals(c.strings("segments"), JsonPointer.segments(c.str("pointer")))
        }
        assertEquals("/linkset/0/https:~1~1example.org~1rel/-", JsonPointer.fromSegments("linkset", 0, "https://example.org/rel", "-"))
        assertFailsWith<IllegalArgumentException> { JsonPointer.segments("no-slash") }
    }

    @Test
    fun jsonPatchFixture() {
        val ops = Fixtures.load("json-patch.json").obj("patch").arr("operations").map { it.jsonObject }
        val patch = JsonPatch()
            .add(ops[0].str("path"), ops[0]["value"]!!)
            .remove(ops[1].str("path"))
            .replace(ops[2].str("path"), ops[2]["value"]!!)
            .move(ops[3].str("from"), ops[3].str("path"))
            .copy(ops[4].str("from"), ops[4].str("path"))
            .test(ops[5].str("path"), ops[5]["value"]!!)
        assertEquals(JsonArray(ops), json(patch.encode()))
        assertEquals(6, patch.size)
        assertEquals(patch.operations, JsonPatch(ops).operations)
        assertEquals(patch.operations, JsonPatch.fromJson(JsonArray(ops).toString()).operations)
        // A null value, an empty object and an empty array survive; strings, numbers and booleans have overloads.
        val p = JsonPatch().add("/a", JsonNull).add("/b", JsonObject(emptyMap())).add("/c", JsonArray(emptyList()))
            .replace("/d", "x").replace("/e", 1.5).test("/f", true)
        assertEquals(
            """[{"op":"add","path":"/a","value":null},{"op":"add","path":"/b","value":{}},{"op":"add","path":"/c","value":[]},""" +
                """{"op":"replace","path":"/d","value":"x"},{"op":"replace","path":"/e","value":1.5},{"op":"test","path":"/f","value":true}]""",
            p.encode(),
        )
        for (bad in listOf("""[{"op":"add","path":"/a"}]""", """[{"op":"nope","path":"/a"}]""", """[{"op":"move","path":"/a"}]""", """[{"op":"remove","path":"a"}]""", """["x"]""", "{}", "nope")) {
            assertFailsWith<IllegalArgumentException>(bad) { JsonPatch.fromJson(bad) }
        }
    }

    @TestFactory
    fun typeQueryFixture(): List<DynamicTest> = Fixtures.cases("type-queries.json") { case ->
        val build = {
            val q = TypeQuery()
            for (step in case.arr("steps").map { it.jsonObject }) {
                val clause = q.relation(step.str("key"))
                if ("allOf" in step) clause.allOf(*step.strings("allOf").toTypedArray()) else clause.anyOf(*step.strings("anyOf").toTypedArray())
            }
            q
        }
        if (case.flag("error")) {
            assertFailsWith<IllegalArgumentException> { build() }
            return@cases
        }
        val q = build()
        assertEquals(case["json"], json(q.encode()))
        assertEquals(q.encode(), TypeQuery.fromJson(q.encode()).encode())
        assertEquals(q, TypeQuery.fromJson(q.toJson()))
    }

    @Test
    fun typeQueryBuilderAndValidation() {
        val q = TypeQuery().allOf("https://schema.org/Person")
            .relation("describedby").anyOf("https://example.org/shapes/person", "https://example.org/shapes/agent")
        assertEquals("""{"type":["https://schema.org/Person"],"describedby":[["https://example.org/shapes/person","https://example.org/shapes/agent"]]}""", q.encode())
        assertEquals("{}", TypeQuery().encode())
        assertTrue(TypeQuery.fromJson("{}").isEmpty)
        assertFalse(TypeQuery.isAbsoluteIri("https://x.example/a b"))
        assertFalse(TypeQuery.isAbsoluteIri("urn:"))
        assertTrue(TypeQuery.isAbsoluteIri("urn:x"))
        for (bad in listOf("[]", """{"type":"x"}""", """{"type":[1]}""", """{"@id":[]}""", "nope")) {
            assertFailsWith<IllegalArgumentException>(bad) { TypeQuery.fromJson(bad) }
        }
        // A copy does not change with the original.
        val copy = q.copy()
        q.allOf("https://schema.org/Event")
        assertFalse(copy == q)
    }

    @Test
    fun slugEncoding() {
        assertEquals("hello.txt", Slug.encode("hello.txt"))
        assertEquals("na%C3%AFve 100%25", Slug.encode("naïve 100%"))
    }

    @Test
    fun urlResolution() {
        // RFC 3986 section 5.4.
        val base = "http://a/b/c/d;p?q"
        val cases = mapOf(
            "g:h" to "g:h", "g" to "http://a/b/c/g", "./g" to "http://a/b/c/g", "g/" to "http://a/b/c/g/", "/g" to "http://a/g",
            "//g" to "http://g", "?y" to "http://a/b/c/d;p?y", "g?y" to "http://a/b/c/g?y", "#s" to "http://a/b/c/d;p?q#s",
            "g#s" to "http://a/b/c/g#s", ";x" to "http://a/b/c/;x", "" to "http://a/b/c/d;p?q", "." to "http://a/b/c/",
            "./" to "http://a/b/c/", ".." to "http://a/b/", "../g" to "http://a/b/g", "../.." to "http://a/", "../../g" to "http://a/g",
            "../../../g" to "http://a/g", "/./g" to "http://a/g", "/../g" to "http://a/g", "g." to "http://a/b/c/g.",
            "..g" to "http://a/b/c/..g", "./../g" to "http://a/b/g", "g/./h" to "http://a/b/c/g/h", "g;x=1/../y" to "http://a/b/c/y",
        )
        for ((ref, expected) in cases) assertEquals(expected, Urls.resolve(ref, base), "resolve($ref)")
        assertNull(Urls.resolve("relative", null))
        assertNull(Urls.resolve("a b", "https://x.example/"))
        assertEquals("https://x.example/p", Urls.resolve("/p", "https://x.example"))
        assertTrue(Urls.contains("https://s.example/a", "https://S.EXAMPLE:443/a/b"))
        assertFalse(Urls.contains("https://s.example/a", "https://s.example/ab"))
        assertEquals("https://s.example/", Urls.canonical("HTTPS://S.Example:443"))
        assertEquals("http://[::1]:8080/x?q", Urls.canonical("http://[::1]:8080/x?q#f"))
        assertEquals("::1", Urls.host("http://[::1]:8080/"))
        assertTrue(Urls.isLoopback("http://[::1]:8080/"))
        assertEquals("my_host", Urls.host("http://my_host:8080/x"))
        assertFailsWith<IllegalArgumentException> { Urls.requireHttp(URI("/relative"), "url") }
        assertFailsWith<IllegalArgumentException> { Urls.requireHttp(URI("ftp://x.example/"), "url") }
    }

    @Test
    fun jsonRoundTrip() {
        val text = """{"a":{},"b":[],"c":{"0":"x","1":"y"},"d":{"1":"y","0":"x"},"e":[{"f":1.0,"g":null}],"h":"é/","i":12345678901234567890}"""
        assertEquals(text, JsonAccess.encode(JsonAccess.decode(text.toByteArray())))
        assertEquals(json("""{"a":1}"""), JsonAccess.decode("\uFEFF{\"a\":1}".toByteArray()))
        assertFailsWith<ProtocolException> { JsonAccess.parse(byteArrayOf(0x7b, 0xff.toByte(), 0x7d), "The body") }
        assertFailsWith<ProtocolException> { JsonAccess.parse("{".toByteArray(), "The body") }
    }
}
