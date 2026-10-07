<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\ProblemDetails;
use Ebremer\Lws\Internal\HeaderLists;

/**
 * A response with an error status. Statuses with a meaning in LWS have a subclass ({@see NotFoundException},
 * {@see ConflictException}, {@see PreconditionFailedException}, …); others are this class (a 5xx is an unknown
 * error). `getCode()` is the status too.
 */
class HttpException extends LwsException
{
    /** The longest body kept, in bytes. */
    public const BODY_LIMIT = 4096;

    private const CLASSES = [
        400 => BadRequestException::class,
        401 => UnauthorizedException::class,
        403 => ForbiddenException::class,
        404 => NotFoundException::class,
        405 => MethodNotAllowedException::class,
        406 => NotAcceptableException::class,
        409 => ConflictException::class,
        410 => GoneException::class,
        412 => PreconditionFailedException::class,
        415 => UnsupportedMediaTypeException::class,
        422 => UnprocessableContentException::class,
        501 => NotImplementedException::class,
        507 => InsufficientStorageException::class,
    ];

    private const REASONS = [
        400 => 'Bad Request', 401 => 'Unauthorized', 402 => 'Payment Required', 403 => 'Forbidden', 404 => 'Not Found',
        405 => 'Method Not Allowed', 406 => 'Not Acceptable', 407 => 'Proxy Authentication Required',
        408 => 'Request Timeout', 409 => 'Conflict', 410 => 'Gone', 411 => 'Length Required',
        412 => 'Precondition Failed', 413 => 'Content Too Large', 414 => 'URI Too Long', 415 => 'Unsupported Media Type',
        416 => 'Range Not Satisfiable', 417 => 'Expectation Failed', 421 => 'Misdirected Request',
        422 => 'Unprocessable Content', 423 => 'Locked', 428 => 'Precondition Required', 429 => 'Too Many Requests',
        500 => 'Internal Server Error', 501 => 'Not Implemented', 502 => 'Bad Gateway', 503 => 'Service Unavailable',
        504 => 'Gateway Timeout', 507 => 'Insufficient Storage',
    ];

    /** The RFC 9457 problem details of the response, if it had any. */
    public readonly ?ProblemDetails $problem;
    /** The response body as text (at most {@see BODY_LIMIT} bytes). */
    public readonly string $body;

    final public function __construct(
        public readonly int $status,
        public readonly string $method,
        public readonly string $url,
        public readonly Headers $headers,
        string $body = '',
    ) {
        $this->problem = ProblemDetails::parse($headers->first('content-type'), $body);
        $this->body = strlen($body) > self::BODY_LIMIT ? substr($body, 0, self::BODY_LIMIT) : $body;
        $reason = self::REASONS[$status] ?? '';
        $message = "$method $url → $status" . ($reason === '' ? '' : " $reason");
        $explanation = $this->problem->detail ?? $this->problem?->title;
        if ($explanation === null && $body !== '' && HeaderLists::essence($headers->first('content-type')) === 'text/plain') {
            $explanation = trim(substr($body, 0, 200));
        }
        if ($explanation !== null && $explanation !== '') {
            $message .= ": $explanation";
        }
        parent::__construct($message, $status);
    }

    /** The exception for an error response: the status-specific subclass where there is one. */
    public static function fromResponse(int $status, string $method, string $url, Headers $headers, string $body = ''): self
    {
        $class = self::CLASSES[$status] ?? self::class;
        return new $class($status, $method, $url, $headers, $body);
    }
}
