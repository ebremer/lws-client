// SPDX-License-Identifier: MIT
import { callout, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

const c = (s) => `<code>${s}</code>`;

export default {
  path: "errors.html",
  title: "Errors",
  description: "How the LWS clients report HTTP failures, authentication problems, protocol violations and webhook verification failures in each language, including RFC 9457 problem details.",
  body: `
<h1>Errors</h1>
<p class="lead">Each client maps HTTP statuses to typed errors that line up with the LWS abstract responses
(<em>not permitted</em>, <em>unknown requester</em>, <em>target not found</em>, <em>conflict</em>, …).
It also attaches the request, the response headers and any RFC 9457 problem details.</p>
<div id="toc" class="toc"></div>

<h2 id="mapping">Status mapping</h2>
${table(
  ["Status", "Concept", "Java", "TypeScript / C++", "Rust (Error::…)", "Go (errors.Is)", "Python", "C#", "Swift (LWSError.…)", "PHP"],
  [
    ["400", "BadRequest", c("BadRequestException"), c("BadRequestError"), c("BadRequest"), c("ErrBadRequest"), c("BadRequestError"), c("BadRequestException"), c("badRequest"), c("BadRequestException")],
    ["401", "Unauthorized (unknown requester)", c("UnauthorizedException"), c("UnauthorizedError"), c("Unauthorized"), c("ErrUnauthorized"), c("UnauthorizedError"), c("UnauthorizedException"), c("unauthorized"), c("UnauthorizedException")],
    ["403", "Forbidden (not permitted)", c("ForbiddenException"), c("ForbiddenError"), c("Forbidden"), c("ErrForbidden"), c("ForbiddenError"), c("ForbiddenException"), c("forbidden"), c("ForbiddenException")],
    ["404", "NotFound", c("NotFoundException"), c("NotFoundError"), c("NotFound"), c("ErrNotFound"), c("NotFoundError"), c("NotFoundException"), c("notFound"), c("NotFoundException")],
    ["405", "MethodNotAllowed (+ Allow)", c("MethodNotAllowedException"), c("MethodNotAllowedError"), c("MethodNotAllowed"), c("ErrMethodNotAllowed"), c("MethodNotAllowedError"), c("MethodNotAllowedException"), c("methodNotAllowed"), c("MethodNotAllowedException")],
    ["406", "NotAcceptable", c("NotAcceptableException"), c("NotAcceptableError"), c("NotAcceptable"), c("ErrNotAcceptable"), c("NotAcceptableError"), c("NotAcceptableException"), c("notAcceptable"), c("NotAcceptableException")],
    ["409", "Conflict", c("ConflictException"), c("ConflictError"), c("Conflict"), c("ErrConflict"), c("ConflictError"), c("ConflictException"), c("conflict"), c("ConflictException")],
    ["410", "Gone", c("GoneException"), c("GoneError"), c("Gone"), c("ErrGone"), c("GoneError") + " (a NotFoundError)", c("GoneException"), c("gone"), c("GoneException")],
    ["412", "PreconditionFailed", c("PreconditionFailedException"), c("PreconditionFailedError"), c("PreconditionFailed"), c("ErrPreconditionFailed"), c("PreconditionFailedError"), c("PreconditionFailedException"), c("preconditionFailed"), c("PreconditionFailedException")],
    ["415", "UnsupportedMediaType (+ Accept-Patch / Accept-Query)", c("UnsupportedMediaTypeException"), c("UnsupportedMediaTypeError"), c("UnsupportedMediaType"), c("ErrUnsupportedMediaType"), c("UnsupportedMediaTypeError"), c("UnsupportedMediaTypeException"), c("unsupportedMediaType"), c("UnsupportedMediaTypeException")],
    ["422", "UnprocessableContent", c("UnprocessableContentException"), c("UnprocessableContentError"), c("UnprocessableContent"), c("ErrUnprocessableContent"), c("UnprocessableContentError"), c("UnprocessableContentException"), c("unprocessableContent"), c("UnprocessableContentException")],
    ["501", "NotImplemented", c("NotImplementedException"), c("NotImplementedError"), c("NotImplemented"), c("ErrNotImplemented"), c("NotImplementedByServerError"), c("HttpNotImplementedException"), c("notImplemented"), c("NotImplementedException")],
    ["507", "InsufficientStorage (quota)", c("InsufficientStorageException"), c("InsufficientStorageError"), c("InsufficientStorage"), c("ErrInsufficientStorage"), c("InsufficientStorageError"), c("InsufficientStorageException"), c("insufficientStorage"), c("InsufficientStorageException")],
    ["other", "HttpError", c("HttpStatusException"), c("HttpError"), c("Http"), c("*HTTPError"), c("HttpError"), c("HttpException"), c("http"), c("HttpException")],
  ],
)}

<h2 id="other">Non-HTTP errors</h2>
${table(
  ["Concept", "When", "Java", "TypeScript / C++", "Rust", "Go", "Python", "C#", "Swift", "PHP"],
  [
    ["AuthenticationError", "Realm mismatch, insecure or filtered AS, issuer mismatch, OAuth error from the token endpoint", c("AuthenticationException"), c("AuthenticationError"), c("Error::Authentication"), c("*AuthenticationError"), c("AuthenticationError"), c("AuthenticationException"), c("LWSError.authentication"), c("AuthenticationException")],
    ["ProtocolError", "A response violates LWS (missing <code>Location</code>, wrong media type, malformed JSON…)", c("LwsProtocolException"), c("ProtocolError"), c("Error::Protocol"), c("*ProtocolError"), c("ProtocolError"), c("ProtocolException"), c("LWSError.protocolError"), c("ProtocolException")],
    ["SignatureVerificationError", "A webhook delivery fails verification", c("SignatureVerificationException"), c("SignatureVerificationError"), c("Error::SignatureVerification"), c("*SignatureVerificationError"), c("SignatureVerificationError"), c("SignatureVerificationException"), c("LWSError.signatureVerification"), c("SignatureVerificationException")],
    ["Transport", "Network failures", c("LwsTransportException"), "native / " + c("TransportError"), c("Error::Transport"), "the <code>net/http</code> error", c("TransportError"), c("LwsTransportException"), c("LWSError.transport"), c("TransportException")],
  ],
)}
<p>All errors share a root: <code>LwsException</code> (Java, where it is unchecked, C#, and PHP, where it is a <code>RuntimeException</code>), <code>LwsError</code> (TypeScript, Python),
<code>lws::Error : std::runtime_error</code> (C++), or a single enum (Rust's <code>Error</code>, Swift's <code>LWSError</code>, whose cases carry the
<code>HTTPError</code>). Go uses
<code>*HTTPError</code> plus sentinels that work with <code>errors.Is</code> and <code>errors.As</code>. Invalid builder input
(a relative IRI in a type query, an access policy without actions) raises the language's ordinary argument
error instead: <code>IllegalArgumentException</code>, <code>TypeError</code>, <code>std::invalid_argument</code>,
<code>ValueError</code>, <code>ArgumentException</code>, a returned <code>error</code>, Rust's <code>Error::InvalidInput</code>, Swift's
<code>LWSError.invalidArgument</code>, or PHP's <code>\\InvalidArgumentException</code>.</p>

<h2 id="handling">Handling errors</h2>
${tabs(S.errors)}

<h2 id="problem">Problem details</h2>
<p>When an error response has an RFC 9457 body (<code>application/problem+json</code>), the error carries it as
<code>problem</code>: <code>type</code>, <code>title</code>, <code>status</code>, <code>detail</code>, <code>instance</code> and
any extension members. The raw response body is kept too (Python, C#, Swift and PHP keep the first 4 KiB).</p>
${tabs(S.problem)}
${callout("note", "304 and 206 are not errors", " A conditional read that returns <code>304 Not Modified</code> yields a normal result flagged <code>notModified</code>, and <code>206 Partial Content</code> is a normal success.")}
`,
};
