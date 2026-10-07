// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.web;

import com.ebremer.lws.driver.clients.ClientRegistry;
import com.ebremer.lws.driver.clients.Inbox;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The clients' webhook inboxes. A delivery is verified with the client's own library, and answered
 * {@code 202} when it verifies, {@code 401} when its signature does not, {@code 400} when it is otherwise
 * refused, and {@code 503} when the client's verifier is unavailable.
 */
@RestController
public class InboxController {

    private final ClientRegistry clients;

    public InboxController(ClientRegistry clients) {
        this.clients = clients;
    }

    @PostMapping("/inbox/{client}/{key}")
    public ResponseEntity<Void> deliver(@PathVariable String client, @PathVariable String key, HttpServletRequest request,
            @RequestBody(required = false) byte[] body) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (String name : Collections.list(request.getHeaderNames())) {
            headers.computeIfAbsent(name.toLowerCase(Locale.ROOT), n -> new ArrayList<>())
                    .addAll(Collections.list(request.getHeaders(name)));
        }
        Inbox.Delivery delivery = clients.deliver(client, key, request.getMethod(), headers, body == null ? new byte[0] : body);
        if (delivery == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.status(delivery.answer()).build();
    }
}
