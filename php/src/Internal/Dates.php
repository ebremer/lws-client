<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Internal;

/**
 * RFC 3339 and HTTP dates.
 *
 * @internal
 */
final class Dates
{
    private const RFC3339 = '/^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?([Zz]|[+-]\d{2}:?\d{2})?)?$/';

    /** Parses an RFC 3339 date-time (or a plain date), or returns null when it is not one. */
    public static function parseRfc3339(?string $text): ?\DateTimeImmutable
    {
        if ($text === null || preg_match(self::RFC3339, trim($text, " \t"), $m) !== 1) {
            return null;
        }
        [$year, $month, $day] = [(int) $m[1], (int) $m[2], (int) $m[3]];
        $hour = (int) ($m[4] ?? 0);
        $minute = (int) ($m[5] ?? 0);
        $second = min((int) ($m[6] ?? 0), 59);
        if (!checkdate($month, $day, $year) || $hour > 23 || $minute > 59) {
            return null;
        }
        $fraction = isset($m[7]) && $m[7] !== '' ? substr(str_pad($m[7], 6, '0'), 0, 6) : '000000';
        $zone = $m[8] ?? '';
        $offset = 'Z';
        if ($zone !== '' && $zone !== 'Z' && $zone !== 'z') {
            $digits = str_replace(':', '', substr($zone, 1));
            $offset = $zone[0] . substr($digits, 0, 2) . ':' . substr($digits, 2, 2);
        }
        $d = \DateTimeImmutable::createFromFormat(
            'Y-m-d H:i:s.u P',
            sprintf('%04d-%02d-%02d %02d:%02d:%02d.%s %s', $year, $month, $day, $hour, $minute, $second, $fraction,
                $offset === 'Z' ? '+00:00' : $offset),
        );
        return $d === false ? null : $d->setTimezone(new \DateTimeZone('UTC'));
    }

    /** Formats an instant as RFC 3339 in UTC (`2026-10-07T12:00:00Z`, fractional seconds only when present). */
    public static function formatRfc3339(\DateTimeInterface $date): string
    {
        $utc = \DateTimeImmutable::createFromInterface($date)->setTimezone(new \DateTimeZone('UTC'));
        $s = $utc->format('Y-m-d\TH:i:s');
        $micros = rtrim($utc->format('u'), '0');
        return $s . ($micros === '' ? '' : '.' . $micros) . 'Z';
    }

    /** Formats an instant as an HTTP date (`Tue, 06 Oct 2026 12:00:00 GMT`). */
    public static function formatHttpDate(\DateTimeInterface $date): string
    {
        return \DateTimeImmutable::createFromInterface($date)->setTimezone(new \DateTimeZone('UTC'))->format('D, d M Y H:i:s') . ' GMT';
    }

    /** Parses an HTTP date (IMF-fixdate), or returns null. */
    public static function parseHttpDate(?string $text): ?\DateTimeImmutable
    {
        if ($text === null) {
            return null;
        }
        $d = \DateTimeImmutable::createFromFormat('!D, d M Y H:i:s \G\M\T', trim($text), new \DateTimeZone('UTC'));
        return $d === false ? null : $d;
    }
}
