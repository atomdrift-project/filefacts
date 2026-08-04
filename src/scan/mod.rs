//! Byte-level scanners shared across format extractors.
//!
//! Each scanner takes a raw byte slice and produces low-level facts:
//! printable-string runs, Shannon entropy, etc. Format-specific extractors
//! call these on whatever subset of the input is appropriate (e.g. just
//! the `.rdata` section for PE, the full file for opaque blobs).

pub(crate) mod ascii;
pub(crate) mod entropy;

/// Convert a ZIP `DateTime` (interpreted as UTC) to Unix seconds.
///
/// ZIP stores timestamps as MS-DOS date/time pairs with no timezone;
/// treating them as UTC is the conventional interpretation for forensic
/// comparison. Returns `None` for years outside the `[1970, 2999]`
/// window — chiefly Mozilla's "zeroed" `(1980, 0, 0)` sentinel, which
/// represents *no recorded timestamp* rather than the literal January
/// 1st of 1980 zero-th day.
pub(crate) fn zip_datetime_to_unix(dt: ::zip::DateTime) -> Option<i64> {
    let year = dt.year();
    if !(1970..=2999).contains(&year) {
        return None;
    }
    let days = days_from_civil(i32::from(year), u32::from(dt.month()), u32::from(dt.day()))?;
    let secs = i64::from(dt.hour()) * 3600 + i64::from(dt.minute()) * 60 + i64::from(dt.second());
    Some(days * 86_400 + secs)
}

/// Days from 1970-01-01 for the given Gregorian `(y, m, d)`, after
/// Howard Hinnant's *date.h* algorithm. Returns `None` for invalid
/// month/day combinations.
pub(crate) fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || d == 0 || d > 31 {
        return None;
    }
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = (y_adj - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(i64::from(era) * 146_097 + i64::from(doe) - 719_468)
}

#[cfg(test)]
mod tests {
    use super::days_from_civil;

    #[test]
    fn epoch_is_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
    }

    #[test]
    fn known_dates() {
        assert_eq!(days_from_civil(2000, 1, 1), Some(10_957));
        assert_eq!(days_from_civil(2024, 1, 1), Some(19_723));
    }

    #[test]
    fn invalid_returns_none() {
        assert!(days_from_civil(2024, 0, 1).is_none());
        assert!(days_from_civil(2024, 13, 1).is_none());
        assert!(days_from_civil(2024, 2, 0).is_none());
        assert!(days_from_civil(2024, 2, 32).is_none());
    }
}
