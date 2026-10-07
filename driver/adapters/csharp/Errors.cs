// SPDX-License-Identifier: MIT
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws;

namespace Ebremer.Lws.Driver.Adapter;

/// <summary>Maps what an operation threw to the protocol's <c>error</c> object (PROTOCOL.md section 3.2).</summary>
internal static class Errors
{
    public const string InvalidArguments = "InvalidArguments";
    public const string Unsupported = "Unsupported";
    public const string Internal = "InternalError";
    public const string Transport = "TransportError";

    /// <summary>
    /// Protocol kinds by exception type. A thrown exception takes the kind of its nearest type here, so an HTTP status
    /// without a type of its own is an <c>HttpError</c>.
    /// </summary>
    private static readonly Dictionary<Type, string> Kinds = new()
    {
        [typeof(BadRequestException)] = "BadRequestError",
        [typeof(UnauthorizedException)] = "UnauthorizedError",
        [typeof(ForbiddenException)] = "ForbiddenError",
        [typeof(NotFoundException)] = "NotFoundError",
        [typeof(MethodNotAllowedException)] = "MethodNotAllowedError",
        [typeof(NotAcceptableException)] = "NotAcceptableError",
        [typeof(ConflictException)] = "ConflictError",
        [typeof(GoneException)] = "GoneError",
        [typeof(PreconditionFailedException)] = "PreconditionFailedError",
        [typeof(UnsupportedMediaTypeException)] = "UnsupportedMediaTypeError",
        [typeof(UnprocessableContentException)] = "UnprocessableContentError",
        [typeof(HttpNotImplementedException)] = "NotImplementedError",
        [typeof(InsufficientStorageException)] = "InsufficientStorageError",
        [typeof(HttpException)] = "HttpError",
        [typeof(AuthenticationException)] = "AuthenticationError",
        [typeof(ProtocolException)] = "ProtocolError",
        [typeof(SignatureVerificationException)] = "SignatureVerificationError",
        [typeof(LwsTransportException)] = Transport,
        [typeof(HttpRequestException)] = Transport,
        [typeof(TimeoutException)] = Transport,
        [typeof(IOException)] = Transport,
        // A JSON failure here is the adapter's own.
        [typeof(JsonException)] = Internal,
        // The library's builders and parsers of caller input reject malformed values with these.
        [typeof(ArgumentException)] = InvalidArguments,
        [typeof(FormatException)] = InvalidArguments,
    };

    /// <summary>The error object for <paramref name="e"/>.</summary>
    public static JsonObject Of(Exception e)
    {
        if (e is AdapterException a) return Error(a.Kind, a.Message);
        string kind = KindOf(e);
        switch (e)
        {
            case HttpException h:
                {
                    JsonObject error = Error(kind, h.Message);
                    error["status"] = h.Status;
                    // RFC 9457 members are flat: the document as received.
                    if (h.Problem is { } problem) error["problem"] = Results.Raw(problem.Raw);
                    if (h is MethodNotAllowedException m) error["allow"] = Results.Strings(m.Allow);
                    if (h is UnsupportedMediaTypeException u) error["acceptPatch"] = Results.Strings(u.AcceptPatch);
                    return error;
                }
            case AuthenticationException auth:
                {
                    JsonObject error = Error(kind, auth.Message);
                    if (auth.Status is { } status) error["status"] = status;
                    Results.Put(error, "oauthError", auth.Error);
                    Results.Put(error, "oauthErrorDescription", auth.ErrorDescription);
                    return error;
                }
        }
        if (kind == Transport) return Error(kind, TransportMessage(e));
        if (kind == Internal) return InternalError(e);
        return Error(kind, e.Message);
    }

    /// <summary>An <c>InternalError</c>: a bug in the adapter or the library. The stack trace goes to the log too.</summary>
    public static JsonObject InternalError(Exception e)
    {
        string trace = e.ToString();
        Console.Error.WriteLine(trace);
        return Error(Internal, trace);
    }

    public static JsonObject Error(string kind, string message) => new() { ["kind"] = kind, ["message"] = message };

    private static string KindOf(Exception e)
    {
        for (Type? t = e.GetType(); t is not null; t = t.BaseType)
        {
            if (Kinds.TryGetValue(t, out string? kind)) return kind;
        }
        return Internal;
    }

    /// <summary>The message, plus the cause when the message does not already say what it was.</summary>
    private static string TransportMessage(Exception e)
    {
        string message = e.Message;
        if (e.InnerException is { } cause && !message.Contains(cause.Message, StringComparison.Ordinal))
        {
            message += $" ({cause.GetType().Name}: {cause.Message})";
        }
        return message;
    }
}
