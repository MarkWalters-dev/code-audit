//! Release-date normalization and day arithmetic for "how far behind".
//!
//! Every source reduces to an ISO `YYYY-MM-DD` string: ISO/RFC 3339
//! timestamps by truncation, Maven file dates from HTTP `Last-Modified`
//! headers. Day differences use Hinnant's days-from-civil algorithm.

/// Leading `YYYY-MM-DD` of an ISO/RFC 3339 timestamp, validated.
pub fn iso_date(stamp: &str) -> Option<String> {
    let date = stamp.get(..10)?;
    valid_ymd(date).then(|| date.to_string())
}

/// `YYYY-MM-DD` from an IMF HTTP date (`Wed, 21 Oct 2015 07:28:00 GMT`).
pub fn http_date(stamp: &str) -> Option<String> {
    let mut parts = stamp.split_whitespace();
    let day: u32 = parts.nth(1)?.parse().ok()?;
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i32 = parts.next()?.parse().ok()?;
    if !(1000..=9999).contains(&year) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

fn valid_ymd(date: &str) -> bool {
    let bytes = date.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(|b| b.is_ascii_digit())
        && bytes[5..7].iter().all(|b| b.is_ascii_digit())
        && bytes[8..10].iter().all(|b| b.is_ascii_digit())
        && (1..=12).contains(&date[5..7].parse::<u32>().unwrap_or(0))
        && (1..=31).contains(&date[8..10].parse::<u32>().unwrap_or(0))
}

/// Absolute days between two `YYYY-MM-DD` dates.
pub fn days_between(a: &str, b: &str) -> Option<i64> {
    Some((days_from_civil(a)? - days_from_civil(b)?).abs())
}

/// Days since 1970-01-01 (Hinnant's algorithm).
fn days_from_civil(date: &str) -> Option<i64> {
    if !valid_ymd(date) {
        return None;
    }
    let y: i64 = date[..4].parse().ok()?;
    let m: i64 = date[5..7].parse().ok()?;
    let d: i64 = date[8..10].parse().ok()?;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_timestamps() {
        assert_eq!(
            iso_date("2026-04-18T01:10:45.796Z"),
            Some("2026-04-18".to_string())
        );
        assert_eq!(iso_date("2026-04-18"), Some("2026-04-18".to_string()));
        assert_eq!(iso_date("2026-13-01T00:00:00Z"), None);
        assert_eq!(iso_date("not a date"), None);
        assert_eq!(
            http_date("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some("2015-10-21".to_string())
        );
        assert_eq!(http_date("21 Oct 2015"), None);
    }

    #[test]
    fn counts_days() {
        assert_eq!(days_between("2026-04-18", "2026-04-18"), Some(0));
        assert_eq!(days_between("2026-04-18", "2026-04-19"), Some(1));
        assert_eq!(days_between("2024-02-28", "2024-03-01"), Some(2)); // leap day
        assert_eq!(days_between("2025-11-02", "2026-04-18"), Some(167));
        assert_eq!(days_between("bogus", "2026-04-18"), None);
    }
}
