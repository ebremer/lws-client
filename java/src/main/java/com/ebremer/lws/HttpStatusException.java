// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/**
 * The server answered with an error status. Specific statuses map to subclasses (for example
 * {@link NotFoundException} for 404); other statuses (including 5xx, the LWS "unknown error") use this
 * class directly. When the response carried an RFC 9457 problem document it is available from
 * {@link #problem()}.
 */
public class HttpStatusException extends LwsException {
    private static final int MAX_BODY = 4096;

    private final String method;
    private final URI uri;
    private final int status;
    private final transient HttpHeaders headers;
    private final transient ProblemDetails problem;
    private final String body;

    public HttpStatusException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(message(method, uri, status, problem));
        this.method = method;
        this.uri = uri;
        this.status = status;
        this.headers = headers != null ? headers : HttpHeaders.of(Map.of(), (a, b) -> true);
        this.problem = problem;
        this.body = body == null ? "" : body;
    }

    private static String message(String method, URI uri, int status, ProblemDetails problem) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(uri).append(" failed with HTTP ").append(status);
        if (problem != null) {
            problem.title().ifPresent(t -> sb.append(": ").append(t));
            problem.detail().ifPresent(d -> sb.append(" (").append(d).append(')'));
        }
        return sb.toString();
    }

    /** The HTTP status code. */
    public int status() {
        return status;
    }

    /** The request method. */
    public String method() {
        return method;
    }

    /** The request URI. */
    public URI uri() {
        return uri;
    }

    /** The response headers. */
    public HttpHeaders headers() {
        return headers;
    }

    /** The RFC 9457 problem details, when present. */
    public Optional<ProblemDetails> problem() {
        return Optional.ofNullable(problem);
    }

    /** The response body as text (truncated to 4 KiB). */
    public String body() {
        return body;
    }

    /** Creates the exception subclass matching {@code status}. */
    public static HttpStatusException of(String method, URI uri, int status, HttpHeaders headers, byte[] bodyBytes) {
        String contentType = headers == null ? null : headers.firstValue("content-type").orElse(null);
        ProblemDetails problem = ProblemDetails.parse(contentType, bodyBytes).orElse(null);
        String body = "";
        if (bodyBytes != null && bodyBytes.length > 0) {
            int n = Math.min(bodyBytes.length, MAX_BODY);
            body = new String(bodyBytes, 0, n, StandardCharsets.UTF_8);
        }
        return switch (status) {
            case 400 -> new BadRequestException(method, uri, status, headers, problem, body);
            case 401 -> new UnauthorizedException(method, uri, status, headers, problem, body);
            case 403 -> new ForbiddenException(method, uri, status, headers, problem, body);
            case 404 -> new NotFoundException(method, uri, status, headers, problem, body);
            case 405 -> new MethodNotAllowedException(method, uri, status, headers, problem, body);
            case 406 -> new NotAcceptableException(method, uri, status, headers, problem, body);
            case 409 -> new ConflictException(method, uri, status, headers, problem, body);
            case 410 -> new GoneException(method, uri, status, headers, problem, body);
            case 412 -> new PreconditionFailedException(method, uri, status, headers, problem, body);
            case 415 -> new UnsupportedMediaTypeException(method, uri, status, headers, problem, body);
            case 422 -> new UnprocessableContentException(method, uri, status, headers, problem, body);
            case 501 -> new NotImplementedException(method, uri, status, headers, problem, body);
            case 507 -> new InsufficientStorageException(method, uri, status, headers, problem, body);
            default -> new HttpStatusException(method, uri, status, headers, problem, body);
        };
    }
}
