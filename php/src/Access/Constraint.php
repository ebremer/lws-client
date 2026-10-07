<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Access;

use Ebremer\Lws\ConstraintOperand;
use Ebremer\Lws\ConstraintOperator;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\Dates;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Json\Json;

/** A constraint of an access policy (ODRL-based): `{leftOperand, operator, rightOperand}`. */
final class Constraint
{
    /** @param mixed $rightOperand a JSON value: a string, a list of strings, … */
    public function __construct(public readonly string $leftOperand, public readonly string $operator, public readonly mixed $rightOperand)
    {
    }

    /** Use for one purpose. */
    public static function purpose(string $purpose): self
    {
        return new self(ConstraintOperand::PURPOSE, ConstraintOperator::EQ, $purpose);
    }

    /** Use for any of several purposes. */
    public static function purposeAnyOf(string ...$purposes): self
    {
        return new self(ConstraintOperand::PURPOSE, ConstraintOperator::IS_ANY_OF, array_values($purposes));
    }

    /** Use by one client application. */
    public static function client(string $clientId): self
    {
        return new self(ConstraintOperand::CLIENT, ConstraintOperator::EQ, $clientId);
    }

    /** Resources of one media type. */
    public static function format(string $mediaType): self
    {
        return new self(ConstraintOperand::FORMAT, ConstraintOperator::EQ, $mediaType);
    }

    /** Resources of any of several media types. */
    public static function formatAnyOf(string ...$mediaTypes): self
    {
        return new self(ConstraintOperand::FORMAT, ConstraintOperator::IS_ANY_OF, array_values($mediaTypes));
    }

    /** Resources of one type. */
    public static function type(string $type): self
    {
        return new self(ConstraintOperand::TYPE, ConstraintOperator::EQ, $type);
    }

    /** Resources of any of several types. */
    public static function typeAnyOf(string ...$types): self
    {
        return new self(ConstraintOperand::TYPE, ConstraintOperator::IS_ANY_OF, array_values($types));
    }

    /** Not before an instant (`dateTime gteq`); a string is kept as written. */
    public static function notBefore(\DateTimeInterface|string $instant): self
    {
        return new self(ConstraintOperand::DATE_TIME, ConstraintOperator::GTEQ, self::instant($instant));
    }

    /** Not after an instant (`dateTime lteq`); a string is kept as written. */
    public static function notAfter(\DateTimeInterface|string $instant): self
    {
        return new self(ConstraintOperand::DATE_TIME, ConstraintOperator::LTEQ, self::instant($instant));
    }

    private static function instant(\DateTimeInterface|string $instant): string
    {
        if (is_string($instant)) {
            if (Dates::parseRfc3339($instant) === null) {
                throw new \InvalidArgumentException("Not an RFC 3339 date-time: $instant");
            }
            return $instant;
        }
        return Dates::formatRfc3339($instant);
    }

    /** @return array<string, mixed> */
    public function toJson(): array
    {
        return ['leftOperand' => $this->leftOperand, 'operator' => $this->operator, 'rightOperand' => $this->rightOperand];
    }

    /** @internal */
    public static function parse(mixed $json): self
    {
        $o = Json::members($json) ?? [];
        $left = JsonAccess::str($o, 'leftOperand');
        $op = JsonAccess::str($o, 'operator');
        if ($left === null || $op === null || !array_key_exists('rightOperand', $o)) {
            throw new ProtocolException('Incomplete constraint');
        }
        return new self($left, $op, $o['rightOperand']);
    }
}
