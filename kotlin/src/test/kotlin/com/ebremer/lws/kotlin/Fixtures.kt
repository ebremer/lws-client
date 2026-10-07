// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.DynamicTest
import java.io.File

/** The shared fixtures of conformance/fixtures (the directory comes from the system property lws.conformance.dir). */
object Fixtures {
    val dir: File = File(System.getProperty("lws.conformance.dir") ?: "../conformance", "fixtures")

    fun load(name: String): JsonObject = Json.parseToJsonElement(File(dir, name).readText()).jsonObject

    /** One dynamic test per case of a fixture's `cases` array, named after the case. */
    fun cases(name: String, test: (JsonObject) -> Unit): List<DynamicTest> =
        load(name)["cases"]!!.jsonArray.map { c ->
            val case = c.jsonObject
            DynamicTest.dynamicTest(case["name"]!!.jsonPrimitive.content) { test(case) }
        }
}

val JsonElement.str: String get() = jsonPrimitive.content

fun JsonObject.str(key: String): String = this[key]!!.jsonPrimitive.content

fun JsonObject.strOrNull(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

fun JsonObject.obj(key: String): JsonObject = this[key]!!.jsonObject

fun JsonObject.arr(key: String): JsonArray = this[key]!!.jsonArray

fun JsonObject.strings(key: String): List<String> = arr(key).map { it.str }

fun JsonObject.flag(key: String): Boolean = (this[key] as? JsonPrimitive)?.content == "true"

fun json(text: String): JsonElement = Json.parseToJsonElement(text)
