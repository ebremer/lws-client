// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.web;

import com.ebremer.lws.driver.DriverProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Guards the MCP endpoint. Whoever can call it can make the clients send requests with their credentials, so:
 * <ul>
 * <li>with {@code lws.driver.token} set, a request must carry it as a Bearer token;</li>
 * <li>without one, the server must listen on loopback only, or it refuses to start;</li>
 * <li>a request with an {@code Origin} header (a browser) is refused unless the origin is in
 * {@code lws.driver.allowed-origins}, which stops a web page from reaching a local driver by DNS rebinding.</li>
 * </ul>
 */
public class McpAccessFilter extends OncePerRequestFilter {

    private final byte[] token;
    private final DriverProperties properties;

    /**
     * @param address the address the server listens on ({@code server.address}); blank means every interface
     * @throws IllegalStateException when there is no token and the address is not loopback
     */
    public McpAccessFilter(DriverProperties properties, String address) {
        this.properties = properties;
        String configured = properties.token();
        this.token = configured == null || configured.isBlank() ? null : configured.getBytes(StandardCharsets.UTF_8);
        if (token == null && !loopback(address)) {
            throw new IllegalStateException("the driver listens on " + (address.isBlank() ? "every interface" : address)
                    + " without lws.driver.token; set a token, or set server.address to a loopback address");
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String origin = request.getHeader("Origin");
        if (origin != null && !properties.allowedOrigins().contains(origin)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "origin not allowed");
            return;
        }
        if (token != null) {
            String authorization = request.getHeader("Authorization");
            byte[] presented = authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)
                    ? authorization.substring(7).trim().getBytes(StandardCharsets.UTF_8) : new byte[0];
            if (!MessageDigest.isEqual(token, presented)) {
                response.setHeader("WWW-Authenticate", "Bearer realm=\"lws-client-driver\"");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private static boolean loopback(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        try {
            return InetAddress.getByName(address).isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
