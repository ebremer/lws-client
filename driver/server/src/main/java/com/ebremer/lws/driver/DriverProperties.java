// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * The driver's settings, under {@code lws.driver}.
 *
 * @param home the driver directory; relative adapter commands resolve against it
 * @param languages the adapters, by language name
 * @param allowedTargets URL prefixes the clients may be pointed at; empty allows any
 * @param token the bearer token that guards the MCP endpoint; required unless the server listens on loopback only
 * @param allowedOrigins browser origins allowed to call the MCP endpoint; a request with any other {@code Origin} is refused
 * @param publicBaseUrl the server's URL as a storage reaches it, for inbox URLs; defaults to the local address
 * @param operationTimeout how long one operation may take before its adapter is stopped
 * @param startupTimeout how long an adapter may take to say hello
 * @param maxClients how many clients may run at once
 * @param idleTimeout how long a client may stay unused before it is stopped
 */
@ConfigurationProperties("lws.driver")
public record DriverProperties(
        @DefaultValue(".") String home,
        Map<String, Language> languages,
        List<String> allowedTargets,
        String token,
        List<String> allowedOrigins,
        String publicBaseUrl,
        @DefaultValue("60s") Duration operationTimeout,
        @DefaultValue("90s") Duration startupTimeout,
        @DefaultValue("16") int maxClients,
        @DefaultValue("2h") Duration idleTimeout) {

    public DriverProperties {
        home = home == null || home.isBlank() ? "." : home;
        languages = languages == null ? Map.of() : Map.copyOf(languages);
        allowedTargets = allowedTargets == null ? List.of() : List.copyOf(allowedTargets);
        allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
    }

    /**
     * The driver directory, absolute. (A {@code Path} property would be bound as a servlet resource, relative
     * to the web server's document base rather than the working directory.)
     */
    public Path homeDirectory() {
        return Path.of(home).toAbsolutePath().normalize();
    }

    /**
     * One language's adapter.
     *
     * @param command the command line that starts it
     * @param environment extra environment variables
     * @param description what it drives, for {@code list_languages}
     */
    public record Language(List<String> command, Map<String, String> environment, String description) {

        public Language {
            command = command == null ? List.of() : List.copyOf(command);
            environment = environment == null ? Map.of() : Map.copyOf(environment);
        }
    }
}
