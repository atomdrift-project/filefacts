//! Calendar arithmetic for the timestamps file formats carry.
//!
//! Every time here is UTC, as Unix seconds. Results are signed: a stamp
//! before 1970 is as much a fact as any other (a zeroed or forged field
//! often lands there) and is kept, not dropped.

/// Seconds from the Windows FILETIME epoch (1601-01-01) to the Unix epoch.
const FILETIME_UNIX_EPOCH_SECS: i64 = 11_644_473_600;

/// A Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as Unix seconds,
/// rounded down. Every `u64` tick count has one.
pub(crate) fn filetime_to_unix(ticks: u64) -> i64 {
    // `u64::MAX / 10^7` is under 2^41, so the cast is exact.
    (ticks / 10_000_000).cast_signed() - FILETIME_UNIX_EPOCH_SECS
}

/// An MS-DOS date and time (as ZIP and RAR store them, with no time zone,
/// read as UTC) as Unix seconds. `None` when a field is out of range: a
/// zero month or day (the zeroed "no time recorded" stamp), a day past the
/// end of its month, an hour past 23 or a minute or second past 59.
pub(crate) fn dos_datetime_to_unix(date: u16, time: u16) -> Option<i64> {
    let year = i32::from(date >> 9) + 1980;
    let month = u32::from((date >> 5) & 0xf);
    let day = u32::from(date & 0x1f);
    let hour = i64::from(time >> 11);
    let minute = i64::from((time >> 5) & 0x3f);
    let second = i64::from(time & 0x1f) * 2;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days from 1970-01-01 to the Gregorian date `(y, m, d)`, after Howard
/// Hinnant's *date.h* algorithm. `None` for a month outside 1–12 or a day
/// outside its month, February 29 counting only in leap years.
pub(crate) fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=month_days).contains(&d) {
        return None;
    }
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = y_adj.rem_euclid(400).cast_unsigned();
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(i64::from(era) * 146_097 + i64::from(doe) - 719_468)
}

/// The Gregorian `(year, month, day)` `days` after 1970-01-01, which may be
/// negative: the inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    // `doy` < 366 and `mp` < 12, so both fit in a `u32`.
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (era * 400 + yoe + i64::from(month <= 2), month, day)
}

/// `unix` as ISO 8601 in UTC, `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn iso8601_utc(unix: i64) -> String {
    let (days, secs) = (unix.div_euclid(86_400), unix.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests;
