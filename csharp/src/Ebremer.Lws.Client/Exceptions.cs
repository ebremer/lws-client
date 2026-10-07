// SPDX-License-Identifier: MIT
using System.Text;
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>
/// Base class of every exception the LWS client throws:
/// <see cref="HttpException"/> (and one subclass per status) when the server answered with an error status,
/// <see cref="AuthenticationException"/> when obtaining an access token failed,
/// <see cref="ProtocolException"/> when a response violates the specification,
/// <see cref="SignatureVerificationException"/> when a webhook delivery fails verification, and
/// <see cref="LwsTransportException"/> when no response arrived.
/// </summary>
public class LwsException : Exception
{
    /// <summary>Creates the exception.</summary>
    public LwsException()
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    public LwsException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">The cause.</param>
    public LwsException(string message, Exception? innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// The server answered with an error status. Specific statuses map to subclasses (for example
/// <see cref="NotFoundException"/> for 404); other statuses, including 5xx (the LWS "unknown error"), use this class.
/// </summary>
public class HttpException : LwsException
{
    /// <summary>The longest body text kept, in bytes.</summary>
    public const int MaxBodyLength = 4096;

    /// <summary>Creates the exception.</summary>
    /// <param name="method">The request method.</param>
    /// <param name="uri">The request URL (of the final redirect hop).</param>
    /// <param name="status">The HTTP status code.</param>
    /// <param name="headers">The response headers.</param>
    /// <param name="problem">The RFC 9457 problem details, if any.</param>
    /// <param name="body">The response body as text (truncated).</param>
    public HttpException(string method, Uri uri, int status, HeaderMap? headers, ProblemDetails? problem, string? body)
        : base(MessageFor(method, uri, status, problem))
    {
        Method = method;
        Uri = uri;
        Status = status;
        Headers = headers ?? HeaderMap.Empty;
        Problem = problem;
        Body = body ?? "";
    }

    /// <summary>The HTTP status code.</summary>
    public int Status { get; }

    /// <summary>The request method.</summary>
    public string Method { get; }

    /// <summary>The request URL.</summary>
    public Uri Uri { get; }

    /// <summary>The response headers.</summary>
    public HeaderMap Headers { get; }

    /// <summary>The RFC 9457 problem details, when the response carried them.</summary>
    public ProblemDetails? Problem { get; }

    /// <summary>The response body as text (truncated to <see cref="MaxBodyLength"/> bytes).</summary>
    public string Body { get; }

    private static string MessageFor(string method, Uri uri, int status, ProblemDetails? problem)
    {
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(Uris.ToText(uri)).Append(" failed with HTTP ").Append(status);
        if (problem?.Title is { } title) sb.Append(": ").Append(title);
        if (problem?.Detail is { } detail) sb.Append(" (").Append(detail).Append(')');
        return sb.ToString();
    }

    /// <summary>Creates the exception subclass matching <paramref name="status"/>.</summary>
    /// <param name="method">The request method.</param>
    /// <param name="uri">The request URL.</param>
    /// <param name="status">The HTTP status code.</param>
    /// <param name="headers">The response headers.</param>
    /// <param name="body">The response body.</param>
    /// <returns>The exception.</returns>
    public static HttpException Create(string method, Uri uri, int status, HeaderMap headers, ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ProblemDetails? problem = ProblemDetails.Parse(headers.GetFirst("content-type"), body);
        string text = body.IsEmpty ? "" : Encoding.UTF8.GetString(body[..Math.Min(body.Length, MaxBodyLength)]);
        return status switch
        {
            400 => new BadRequestException(method, uri, headers, problem, text),
            401 => new UnauthorizedException(method, uri, headers, problem, text),
            403 => new ForbiddenException(method, uri, headers, problem, text),
            404 => new NotFoundException(method, uri, headers, problem, text),
            405 => new MethodNotAllowedException(method, uri, headers, problem, text),
            406 => new NotAcceptableException(method, uri, headers, problem, text),
            409 => new ConflictException(method, uri, headers, problem, text),
            410 => new GoneException(method, uri, headers, problem, text),
            412 => new PreconditionFailedException(method, uri, headers, problem, text),
            415 => new UnsupportedMediaTypeException(method, uri, headers, problem, text),
            422 => new UnprocessableContentException(method, uri, headers, problem, text),
            501 => new HttpNotImplementedException(method, uri, headers, problem, text),
            507 => new InsufficientStorageException(method, uri, headers, problem, text),
            _ => new HttpException(method, uri, status, headers, problem, text),
        };
    }
}

/// <summary><c>400 Bad Request</c>.</summary>
public class BadRequestException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 400, headers, problem, body);

/// <summary>
/// <c>401 Unauthorized</c> remained after authentication handling (LWS "unknown requester"). The parsed
/// <c>WWW-Authenticate</c> challenges tell which authorization server to use.
/// </summary>
public class UnauthorizedException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 401, headers, problem, body)
{
    /// <summary>The challenges of the <c>WWW-Authenticate</c> response header.</summary>
    public IReadOnlyList<AuthChallenge> Challenges => WwwAuthenticate.Parse(Headers.GetAll("www-authenticate"));
}

/// <summary><c>403 Forbidden</c> (LWS "not permitted").</summary>
public class ForbiddenException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 403, headers, problem, body);

/// <summary><c>404 Not Found</c> (LWS "target not found").</summary>
public class NotFoundException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 404, headers, problem, body);

/// <summary><c>405 Method Not Allowed</c>; <see cref="Allow"/> lists the methods the resource supports.</summary>
public class MethodNotAllowedException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 405, headers, problem, body)
{
    /// <summary>The methods of the <c>Allow</c> header.</summary>
    public IReadOnlyList<string> Allow => HeaderLists.Split(Headers.GetAll("allow"));
}

/// <summary><c>406 Not Acceptable</c>.</summary>
public class NotAcceptableException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 406, headers, problem, body);

/// <summary><c>409 Conflict</c> (LWS "conflict"), e.g. deleting a non-empty container without recursion.</summary>
public class ConflictException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 409, headers, problem, body);

/// <summary><c>410 Gone</c>.</summary>
public class GoneException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 410, headers, problem, body);

/// <summary><c>412 Precondition Failed</c>: an <c>If-Match</c> / <c>If-None-Match</c> condition did not hold.</summary>
public class PreconditionFailedException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 412, headers, problem, body);

/// <summary>
/// <c>415 Unsupported Media Type</c>. For PATCH, <see cref="AcceptPatch"/> lists the supported patch formats; for
/// QUERY, <see cref="AcceptQuery"/> lists the supported query formats.
/// </summary>
public class UnsupportedMediaTypeException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 415, headers, problem, body)
{
    /// <summary>The media types of the <c>Accept-Patch</c> header.</summary>
    public IReadOnlyList<string> AcceptPatch => HeaderLists.Split(Headers.GetAll("accept-patch"));

    /// <summary>The media types of the <c>Accept-Query</c> header.</summary>
    public IReadOnlyList<string> AcceptQuery => HeaderLists.Split(Headers.GetAll("accept-query"));
}

/// <summary><c>422 Unprocessable Content</c>.</summary>
public class UnprocessableContentException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 422, headers, problem, body);

/// <summary>
/// <c>501 Not Implemented</c> (the contract's <c>NotImplementedError</c>; named so that it does not clash with
/// <see cref="System.NotImplementedException"/>).
/// </summary>
public class HttpNotImplementedException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 501, headers, problem, body);

/// <summary><c>507 Insufficient Storage</c> (LWS "quota exceeded").</summary>
public class InsufficientStorageException(string method, Uri uri, HeaderMap? headers, ProblemDetails? problem, string? body)
    : HttpException(method, uri, 507, headers, problem, body);

/// <summary>
/// Obtaining an access token failed: the challenge realm did not contain the request URL, the authorization
/// server was insecure or rejected by the filter, its metadata was invalid, or the token exchange was refused
/// (then <see cref="Error"/> carries the OAuth <c>error</c> code and <see cref="Status"/> the HTTP status).
/// </summary>
public class AuthenticationException : LwsException
{
    /// <summary>Creates the exception.</summary>
    public AuthenticationException()
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    public AuthenticationException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">The cause.</param>
    public AuthenticationException(string message, Exception? innerException) : base(message, innerException)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="error">The OAuth 2.0 <c>error</c> code.</param>
    /// <param name="errorDescription">The OAuth 2.0 <c>error_description</c>.</param>
    /// <param name="status">The HTTP status of the response that failed, if any.</param>
    /// <param name="innerException">The cause.</param>
    public AuthenticationException(string message, string? error, string? errorDescription, int? status, Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
        ErrorDescription = errorDescription;
        Status = status;
    }

    /// <summary>The OAuth 2.0 <c>error</c> code (RFC 6749 section 5.2), when the token endpoint returned one.</summary>
    public string? Error { get; }

    /// <summary>The OAuth 2.0 <c>error_description</c>, when present.</summary>
    public string? ErrorDescription { get; }

    /// <summary>The HTTP status of the authorization server response that failed, when there was one.</summary>
    public int? Status { get; }
}

/// <summary>A server response violates the LWS specification (a missing <c>Location</c>, a wrong media type, bad JSON, …).</summary>
public class ProtocolException : LwsException
{
    /// <summary>Creates the exception.</summary>
    public ProtocolException()
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    public ProtocolException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">The cause.</param>
    public ProtocolException(string message, Exception? innerException) : base(message, innerException)
    {
    }
}

/// <summary>A webhook delivery failed verification (digest, signature, key, time window or storage checks).</summary>
public class SignatureVerificationException : LwsException
{
    /// <summary>Creates the exception.</summary>
    public SignatureVerificationException()
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What failed.</param>
    public SignatureVerificationException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What failed.</param>
    /// <param name="innerException">The cause.</param>
    public SignatureVerificationException(string message, Exception? innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// No response arrived: connection refused, TLS failure or timeout. The <see cref="Exception.InnerException"/> is
/// the <see cref="HttpRequestException"/>, <see cref="IOException"/> or <see cref="TimeoutException"/>.
/// </summary>
public class LwsTransportException : LwsException
{
    /// <summary>Creates the exception.</summary>
    public LwsTransportException()
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    public LwsTransportException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">The cause.</param>
    public LwsTransportException(string message, Exception? innerException) : base(message, innerException)
    {
    }
}
