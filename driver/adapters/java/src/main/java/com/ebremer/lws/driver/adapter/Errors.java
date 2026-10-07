// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.adapter;

import com.ebremer.lws.AuthenticationException;
import com.ebremer.lws.BadRequestException;
import com.ebremer.lws.ConflictException;
import com.ebremer.lws.ForbiddenException;
import com.ebremer.lws.GoneException;
import com.ebremer.lws.HttpStatusException;
import com.ebremer.lws.InsufficientStorageException;
import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.LwsTransportException;
import com.ebremer.lws.MethodNotAllowedException;
import com.ebremer.lws.NotAcceptableException;
import com.ebremer.lws.NotFoundException;
import com.ebremer.lws.NotImplementedException;
import com.ebremer.lws.PreconditionFailedException;
import com.ebremer.lws.SignatureVerificationException;
import com.ebremer.lws.UnauthorizedException;
import com.ebremer.lws.UnprocessableContentException;
import com.ebremer.lws.UnsupportedMediaTypeException;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.util.Map;

/** Maps what an operation threw to the protocol's {@code error} object (PROTOCOL.md section 3.2). */
final class Errors {
    static final String INVALID_ARGUMENTS = "InvalidArguments";
    static final String UNSUPPORTED = "Unsupported";
    static final String INTERNAL = "InternalError";

    /**
     * Protocol kinds by exception class. A thrown exception takes the kind of its nearest class here, so
     * {@code HttpTimeoutException} is a {@code TransportError} through {@code IOException}, and an
     * HTTP status without a class of its own is an {@code HttpError}.
     */
    private static final Map<Class<?>, String> KINDS = Map.ofEntries(
            Map.entry(BadRequestException.class, "BadRequestError"),
            Map.entry(UnauthorizedException.class, "UnauthorizedError"),
            Map.entry(ForbiddenException.class, "ForbiddenError"),
            Map.entry(NotFoundException.class, "NotFoundError"),
            Map.entry(MethodNotAllowedException.class, "MethodNotAllowedError"),
            Map.entry(NotAcceptableException.class, "NotAcceptableError"),
            Map.entry(ConflictException.class, "ConflictError"),
            Map.entry(GoneException.class, "GoneError"),
            Map.entry(PreconditionFailedException.class, "PreconditionFailedError"),
            Map.entry(UnsupportedMediaTypeException.class, "UnsupportedMediaTypeError"),
            Map.entry(UnprocessableContentException.class, "UnprocessableContentError"),
            Map.entry(NotImplementedException.class, "NotImplementedError"),
            Map.entry(InsufficientStorageException.class, "InsufficientStorageError"),
            Map.entry(HttpStatusException.class, "HttpError"),
            Map.entry(AuthenticationException.class, "AuthenticationError"),
            Map.entry(LwsProtocolException.class, "ProtocolError"),
            Map.entry(SignatureVerificationException.class, "SignatureVerificationError"),
            Map.entry(LwsTransportException.class, "TransportError"),
            Map.entry(UncheckedIOException.class, "TransportError"),
            // Jackson's exceptions are IOExceptions, but a JSON failure here is the adapter's own.
            Map.entry(JacksonException.class, INTERNAL),
            Map.entry(IOException.class, "TransportError"),
            // The library's builders and parsers of caller input reject malformed values this way.
            Map.entry(IllegalArgumentException.class, INVALID_ARGUMENTS));

    private Errors() {}

    /** The error object for {@code e}. */
    static ObjectNode of(Throwable e) {
        if (e instanceof AdapterException a) return error(a.kind(), a.getMessage());
        String kind = kind(e);
        if (e instanceof HttpStatusException h) {
            ObjectNode error = error(kind, h.getMessage());
            error.put("status", h.status());
            h.problem().ifPresent(p -> error.set("problem", p.raw()));
            if (h instanceof MethodNotAllowedException m) error.set("allow", Results.strings(m.allow()));
            if (h instanceof UnsupportedMediaTypeException u) error.set("acceptPatch", Results.strings(u.acceptPatch()));
            return error;
        }
        if (e instanceof AuthenticationException a) {
            ObjectNode error = error(kind, a.getMessage());
            a.error().ifPresent(v -> error.put("oauthError", v));
            a.errorDescription().ifPresent(v -> error.put("oauthErrorDescription", v));
            return error;
        }
        if (kind.equals("TransportError")) return error(kind, transportMessage(e));
        if (kind.equals(INTERNAL)) return internal(e);
        return error(kind, String.valueOf(e.getMessage()));
    }

    /** An {@code InternalError}: a bug in the adapter or the library. The stack trace goes to the log too. */
    static ObjectNode internal(Throwable e) {
        StringWriter trace = new StringWriter();
        e.printStackTrace(new PrintWriter(trace));
        System.err.print(trace);
        return error(INTERNAL, trace.toString());
    }

    static ObjectNode error(String kind, String message) {
        ObjectNode error = Results.object();
        error.put("kind", kind);
        error.put("message", message);
        return error;
    }

    private static String kind(Throwable e) {
        for (Class<?> c = e.getClass(); c != null; c = c.getSuperclass()) {
            String kind = KINDS.get(c);
            if (kind != null) return kind;
        }
        return INTERNAL;
    }

    /** The message, plus the cause when the message does not already say what it was. */
    private static String transportMessage(Throwable e) {
        String message = String.valueOf(e.getMessage());
        Throwable cause = e.getCause();
        if (cause != null && (cause.getMessage() == null || !message.contains(cause.getMessage()))) {
            message += " (" + cause + ")";
        }
        return message;
    }
}
