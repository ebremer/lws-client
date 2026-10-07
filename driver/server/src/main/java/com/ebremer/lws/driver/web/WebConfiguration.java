// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.web;

import com.ebremer.lws.driver.DriverProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Puts {@link McpAccessFilter} in front of the MCP endpoint. */
@Configuration
public class WebConfiguration {

    @Bean
    public FilterRegistrationBean<McpAccessFilter> mcpAccessFilter(DriverProperties properties,
            @Value("${server.address:}") String address,
            @Value("${spring.ai.mcp.server.streamable-http.mcp-endpoint:/mcp}") String endpoint) {
        FilterRegistrationBean<McpAccessFilter> registration = new FilterRegistrationBean<>(new McpAccessFilter(properties, address));
        registration.addUrlPatterns(endpoint, endpoint + "/*");
        return registration;
    }
}
