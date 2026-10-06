// SPDX-License-Identifier: MIT
package com.ebremer.lws.access;

import com.ebremer.lws.Lws;
import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * An ODRL constraint limiting an access policy ({@code leftOperand operator rightOperand}). All
 * constraints of a policy must be satisfied.
 *
 * @param leftOperand {@code client}, {@code format}, {@code type}, {@code purpose}, {@code dateTime}, …
 * @param operator {@code eq}, {@code isAnyOf}, {@code gteq}, {@code lteq}, …
 * @param rightOperand the comparison value (a string, or an array for {@code isAnyOf})
 */
public record Constraint(String leftOperand, String operator, JsonNode rightOperand) {
    public Constraint {
        Objects.requireNonNull(leftOperand, "leftOperand");
        Objects.requireNonNull(operator, "operator");
        Objects.requireNonNull(rightOperand, "rightOperand");
    }

    /** A generic constraint; {@code rightOperand} may be any Jackson-serialisable value. */
    public static Constraint of(String leftOperand, String operator, Object rightOperand) {
        return new Constraint(leftOperand, operator, Json.valueToTree(rightOperand));
    }

    /** {@code purpose eq <purpose>}. */
    public static Constraint purpose(URI purpose) {
        return of(Lws.Access.OPERAND_PURPOSE, Lws.Access.OPERATOR_EQ, purpose.toString());
    }

    /** {@code purpose isAnyOf [purposes]}. */
    public static Constraint purposeAnyOf(Collection<URI> purposes) {
        return of(Lws.Access.OPERAND_PURPOSE, Lws.Access.OPERATOR_IS_ANY_OF, strings(purposes));
    }

    /** {@code client eq <client>} — restricts access to one client application. */
    public static Constraint client(URI clientId) {
        return of(Lws.Access.OPERAND_CLIENT, Lws.Access.OPERATOR_EQ, clientId.toString());
    }

    /** {@code format eq <mediaType>}. */
    public static Constraint format(String mediaType) {
        return of(Lws.Access.OPERAND_FORMAT, Lws.Access.OPERATOR_EQ, mediaType);
    }

    /** {@code format isAnyOf [mediaTypes]}. */
    public static Constraint formatAnyOf(Collection<String> mediaTypes) {
        return of(Lws.Access.OPERAND_FORMAT, Lws.Access.OPERATOR_IS_ANY_OF, List.copyOf(mediaTypes));
    }

    /** {@code type eq <type>} — matches the resource's {@code rel="type"} links. */
    public static Constraint type(URI type) {
        return of(Lws.Access.OPERAND_TYPE, Lws.Access.OPERATOR_EQ, type.toString());
    }

    /** {@code type isAnyOf [types]}. */
    public static Constraint typeAnyOf(Collection<URI> types) {
        return of(Lws.Access.OPERAND_TYPE, Lws.Access.OPERATOR_IS_ANY_OF, strings(types));
    }

    /** {@code dateTime gteq <instant>} — access starts at {@code instant}. */
    public static Constraint notBefore(Instant instant) {
        return of(Lws.Access.OPERAND_DATE_TIME, Lws.Access.OPERATOR_GTEQ, instant.toString());
    }

    /** {@code dateTime lteq <instant>} — access ends at {@code instant}. */
    public static Constraint notAfter(Instant instant) {
        return of(Lws.Access.OPERAND_DATE_TIME, Lws.Access.OPERATOR_LTEQ, instant.toString());
    }

    ObjectNode toJson() {
        ObjectNode o = Json.object();
        o.put("leftOperand", leftOperand);
        o.put("operator", operator);
        o.set("rightOperand", rightOperand);
        return o;
    }

    static Constraint parse(JsonNode n) {
        String l = Json.text(n, "leftOperand");
        String op = Json.text(n, "operator");
        JsonNode r = n.get("rightOperand");
        if (l == null || op == null || r == null) throw new LwsProtocolException("Incomplete constraint");
        return new Constraint(l, op, r);
    }

    private static List<String> strings(Collection<URI> uris) {
        return uris.stream().map(URI::toString).toList();
    }
}
