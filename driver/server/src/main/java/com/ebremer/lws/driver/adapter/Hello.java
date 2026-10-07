// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.adapter;

import java.util.ArrayList;
import java.util.List;
import tools.jackson.databind.JsonNode;

/**
 * What an adapter announces when it starts: the protocol it speaks, its language, the library it drives,
 * and the operations it implements.
 */
public record Hello(String protocol, String language, String library, List<String> operations) {

    public Hello {
        operations = List.copyOf(operations);
    }

    static Hello of(JsonNode hello) {
        String protocol = text(hello, "protocol");
        String language = text(hello, "language");
        String library = text(hello, "library");
        JsonNode ops = hello.get("operations");
        if (ops == null || !ops.isArray()) {
            throw new IllegalArgumentException("operations is not a list");
        }
        List<String> operations = new ArrayList<>();
        for (JsonNode op : ops) {
            if (!op.isString()) {
                throw new IllegalArgumentException("an operation is not a string");
            }
            operations.add(op.asString());
        }
        return new Hello(protocol, language, library, operations);
    }

    public boolean supports(String operation) {
        return operations.contains(operation);
    }

    private static String text(JsonNode node, String name) {
        JsonNode value = node.get(name);
        if (value == null || !value.isString()) {
            throw new IllegalArgumentException(name + " is not a string");
        }
        return value.asString();
    }
}
