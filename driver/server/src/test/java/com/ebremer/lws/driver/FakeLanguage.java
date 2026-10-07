// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

import java.nio.file.Path;
import org.springframework.test.context.DynamicPropertyRegistry;

/** Registers the {@link FakeAdapter} as the driver's only language, {@code fake}. */
final class FakeLanguage {

    private FakeLanguage() {
    }

    static void register(DynamicPropertyRegistry registry) {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        registry.add("lws.driver.languages.fake.command[0]", () -> java);
        registry.add("lws.driver.languages.fake.command[1]", () -> "-cp");
        registry.add("lws.driver.languages.fake.command[2]", () -> System.getProperty("java.class.path"));
        registry.add("lws.driver.languages.fake.command[3]", () -> FakeAdapter.class.getName());
        registry.add("lws.driver.languages.fake.description", () -> "the tests' fake adapter");
    }
}
