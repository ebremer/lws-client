// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Access to the shared conformance fixtures in {@code ../conformance/fixtures}. */
public final class Fixtures {
    private Fixtures() {}

    public static Path dir() {
        String configured = System.getProperty("lws.conformance.dir");
        Path base = configured != null ? Path.of(configured) : Path.of("..", "conformance");
        return base.resolve("fixtures");
    }

    public static JsonNode json(String relative) {
        try {
            return Json.MAPPER.readTree(Files.readAllBytes(dir().resolve(relative)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
