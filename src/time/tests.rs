use super::*;

#[test]
fn epoch_is_zero() {
    assert_eq!(days_from_civil(1970, 1, 1), Some(0));
}

#[test]
fn known_dates() {
    assert_eq!(days_from_civil(2000, 1, 1), Some(10_957));
    assert_eq!(days_from_civil(2024, 1, 1), Some(19_723));
    assert_eq!(days_from_civil(1900, 1, 1), Some(-25_567));
}

#[test]
fn invalid_returns_none() {
    assert!(days_from_civil(2024, 0, 1).is_none());
    assert!(days_from_civil(2024, 13, 1).is_none());
    assert!(days_from_civil(2024, 2, 0).is_none());
    assert!(days_from_civil(2024, 2, 32).is_none());
}

#[test]
fn day_past_the_end_of_its_month_is_invalid() {
    assert!(days_from_civil(2023, 2, 29).is_none());
    assert!(days_from_civil(2024, 2, 30).is_none());
    assert!(days_from_civil(2024, 4, 31).is_none());
    assert!(days_from_civil(1900, 2, 29).is_none());
    assert!(days_from_civil(2000, 2, 29).is_some());
    assert!(days_from_civil(2024, 2, 29).is_some());
    assert!(days_from_civil(2024, 12, 31).is_some());
}

#[test]
fn civil_round_trips() {
    for days in [-719_468, -25_567, -1, 0, 1, 10_957, 19_723, 2_932_896] {
        let (y, m, d) = civil_from_days(days);
        let y = i32::try_from(y).unwrap();
        assert_eq!(days_from_civil(y, m, d), Some(days), "{y}-{m}-{d}");
    }
}

#[test]
fn filetime_is_signed_unix_seconds() {
    assert_eq!(filetime_to_unix(116_444_736_000_000_000), 0);
    assert_eq!(filetime_to_unix(0), -11_644_473_600);
    let y1900 = (11_644_473_600u64 - 2_208_988_800) * 10_000_000;
    assert_eq!(filetime_to_unix(y1900), -2_208_988_800);
    assert_eq!(filetime_to_unix(u64::MAX), 1_833_029_933_770);
}

#[test]
fn iso8601_renders_dates_either_side_of_the_epoch() {
    assert_eq!(iso8601_utc(1_705_305_600), "2024-01-15T08:00:00Z");
    assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(iso8601_utc(-1), "1969-12-31T23:59:59Z");
    assert_eq!(iso8601_utc(-2_208_988_800), "1900-01-01T00:00:00Z");
    assert_eq!(iso8601_utc(-11_644_473_600), "1601-01-01T00:00:00Z");
}

/// An MS-DOS date and time packs a year from 1980, month, day, and
/// two-second time fields.
fn dos(y: u16, mo: u16, d: u16, h: u16, mi: u16, s: u16) -> (u16, u16) {
    (
        ((y - 1980) << 9) | (mo << 5) | d,
        (h << 11) | (mi << 5) | (s / 2),
    )
}

#[test]
fn dos_datetime_reads_as_utc() {
    let (date, time) = dos(2024, 1, 15, 8, 0, 0);
    assert_eq!(dos_datetime_to_unix(date, time), Some(1_705_305_600));
    let (date, time) = dos(1980, 1, 1, 23, 59, 58);
    assert_eq!(dos_datetime_to_unix(date, time), Some(315_619_198));
}

#[test]
fn dos_datetime_out_of_range_is_none() {
    // The zeroed "no time recorded" stamp: month and day zero.
    assert_eq!(dos_datetime_to_unix(0, 0), None);
    let (date, _) = dos(2023, 2, 29, 0, 0, 0);
    assert_eq!(dos_datetime_to_unix(date, 0), None);
    let (date, _) = dos(2024, 1, 1, 0, 0, 0);
    assert_eq!(dos_datetime_to_unix(date, 24 << 11), None);
    assert_eq!(dos_datetime_to_unix(date, 60 << 5), None);
    assert_eq!(dos_datetime_to_unix(date, 30), None);
}
