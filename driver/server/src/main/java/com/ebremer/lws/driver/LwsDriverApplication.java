// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * The lws-client driver: an MCP server whose tools make one of the six lws-client libraries perform LWS
 * operations, so that a test service such as Touchstone can drive each client and judge what it sends.
 */
@SpringBootApplication
@EnableConfigurationProperties(DriverProperties.class)
@EnableScheduling
public class LwsDriverApplication {

    public static void main(String[] args) {
        SpringApplication.run(LwsDriverApplication.class, args);
    }
}
