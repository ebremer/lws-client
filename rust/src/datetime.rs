// SPDX-License-Identifier: MIT
//! Minimal RFC 3339 date-time parsing and formatting on top of [`std::time::SystemTime`], so
//! the public API does not force a particular date/time crate on users.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Parses an RFC 3339 / ISO 8601 date-time such as `2025-11-24T12:00:00Z` or
/// `2026-03-26T10:30:00.250+02:00`. Returns `None` for anything it cannot parse.
///
/// ```
/// use lws_client::datetime::{format_rfc3339, parse_rfc3339};
/// let t = parse_rfc3339("2026-06-09T12:00:00Z").unwrap();
/// assert_eq!(format_rfc3339(t), "2026-06-09T12:00:00Z");
/// assert!(parse_rfc3339("not-a-date").is_none());
/// ```
pub fn parse_rfc3339(input: &str) -> Option<SystemTime> {
    let b = input.trim().as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |s: &[u8]| -> Option<u32> {
        if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(s).ok()?.parse().ok()
    };
    let year = num(&b[0..4])? as i64;
    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let month = num(&b[5..7])?;
    let day = num(&b[8..10])?;
    let hour = num(&b[11..13])?;
    let minute = num(&b[14..16])?;
    let mut second = num(&b[17..19])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    if second == 60 {
        second = 59; // leap second: clamp
    }
    let mut i = 19;
    let mut nanos: u32 = 0;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let frac = &b[start..i];
        let mut n: u32 = 0;
        for k in 0..9 {
            n = n * 10 + frac.get(k).map(|d| (d - b'0') as u32).unwrap_or(0);
        }
        nanos = n;
    }
    let offset_secs: i64 = match b.get(i) {
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
            let oh = num(&b[i + 1..i + 3])? as i64;
            let om = num(&b[i + 4..i + 6])? as i64;
            if oh > 23 || om > 59 {
                return None;
            }
            let s = oh * 3600 + om * 60;
            if *sign == b'+' { s } else { -s }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let secs =
        days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64 - offset_secs;
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(secs as u64, nanos))
    } else {
        let back = Duration::new(secs.unsigned_abs(), 0);
        UNIX_EPOCH
            .checked_sub(back)?
            .checked_add(Duration::new(0, nanos))
    }
}

/// Formats a time as an RFC 3339 UTC date-time (`YYYY-MM-DDTHH:MM:SSZ`, with a fractional part
/// only when the time has sub-second precision).
pub fn format_rfc3339(time: SystemTime) -> String {
    let (secs, nanos) = match time.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            if d.subsec_nanos() == 0 {
                (-(d.as_secs() as i64), 0)
            } else {
                (-(d.as_secs() as i64) - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    };
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let mut out = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );
    if nanos != 0 {
        let frac = format!("{nanos:09}");
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }
    out.push('Z');
    out
}

/// Seconds since the Unix epoch (saturating at zero for earlier times).
#[cfg_attr(not(feature = "crypto"), allow(dead_code))]
pub(crate) fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Converts Unix seconds to a [`SystemTime`].
pub(crate) fn from_unix_seconds(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        _ => 28,
    }
}

// Howard Hinnant's civil calendar algorithms.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (m as u64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for s in [
            "1970-01-01T00:00:00Z",
            "2025-11-24T12:00:00Z",
            "2000-02-29T23:59:59Z",
            "1969-12-31T23:59:59Z",
            "2026-03-26T10:30:00.25Z",
        ] {
            assert_eq!(format_rfc3339(parse_rfc3339(s).unwrap()), s);
        }
    }

    #[test]
    fn offsets_and_fractions() {
        let a = parse_rfc3339("2026-03-26T12:30:00+02:00").unwrap();
        let b = parse_rfc3339("2026-03-26T10:30:00Z").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            unix_seconds(parse_rfc3339("2026-09-21T14:13:20Z").unwrap()),
            1_790_000_000
        );
        assert!(parse_rfc3339("2026-02-30T00:00:00Z").is_none());
        assert!(parse_rfc3339("2026-01-01T00:00:00").is_none());
        assert!(parse_rfc3339("2026-01-01T00:00:00.Z").is_none());
    }
}
