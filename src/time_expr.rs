use chrono::{DateTime, Datelike, Duration, Local, NaiveDate, NaiveDateTime, Weekday};
use std::fs;
use std::path::{Path, PathBuf};

pub const SNAPSHOT_FMT: &str = "%Y-%m-%dT%H-%M-%S";

pub fn format_snapshot_name(dt: DateTime<Local>) -> String {
    dt.format(SNAPSHOT_FMT).to_string()
}

fn parse_snapshot_name(name: &str) -> Option<DateTime<Local>> {
    let naive = NaiveDateTime::parse_from_str(name, SNAPSHOT_FMT).ok()?;
    naive.and_local_timezone(Local).single()
}

fn weekday_from_str(s: &str) -> Option<Weekday> {
    Some(match s.to_lowercase().as_str() {
        "mon" | "monday" => Weekday::Mon,
        "tue" | "tues" | "tuesday" => Weekday::Tue,
        "wed" | "wednesday" => Weekday::Wed,
        "thu" | "thur" | "thursday" => Weekday::Thu,
        "fri" | "friday" => Weekday::Fri,
        "sat" | "saturday" => Weekday::Sat,
        "sun" | "sunday" => Weekday::Sun,
        _ => return None,
    })
}

fn most_recent_past(weekday: Weekday, now: DateTime<Local>) -> DateTime<Local> {
    let mut d = now.date_naive();
    loop {
        d -= Duration::days(1);
        if d.weekday() == weekday {
            return end_of_day(d);
        }
    }
}

fn end_of_day(d: NaiveDate) -> DateTime<Local> {
    let naive = d.and_hms_opt(23, 59, 59).unwrap();
    naive.and_local_timezone(Local).single().unwrap()
}

fn parse_unit(unit: &str) -> Option<fn(i64, DateTime<Local>) -> Option<DateTime<Local>>> {
    match unit {
        "minute" | "minutes" | "min" | "m" => Some(|n, now| Some(now - Duration::minutes(n))),
        "hour" | "hours" | "hr" | "h" => Some(|n, now| Some(now - Duration::hours(n))),
        "day" | "days" | "d" => Some(|n, now| Some(now - Duration::days(n))),
        "week" | "weeks" | "w" => Some(|n, now| Some(now - Duration::weeks(n))),
        "month" | "months" | "mo" => Some(|n, now| {
            let months = chrono::Months::new(n as u32);
            now.date_naive().checked_sub_months(months).map(end_of_day)
        }),
        _ => None,
    }
}

fn parse_relative(expr: &str, now: DateTime<Local>) -> Option<DateTime<Local>> {
    let head = expr.strip_suffix("-ago")?;

    // "3-days" / "1-week" form
    if let Some((num_str, unit_str)) = head.split_once('-')
        && let Ok(n) = num_str.parse::<i64>()
        && let Some(f) = parse_unit(unit_str)
    {
        return f(n, now);
    }

    // combined "2h" / "30m" / "3d" form
    let split_at = head.find(|c: char| !c.is_ascii_digit())?;
    let (num_str, unit_str) = head.split_at(split_at);
    let n: i64 = num_str.parse().ok()?;
    let f = parse_unit(unit_str)?;
    f(n, now)
}

/// Reduce a time expression to a target instant. Returns None if `expr`
/// isn't a recognized time expression — caller should then try an exact
/// snapshot-name match (named snapshots).
pub fn resolve_target(expr: &str, now: DateTime<Local>) -> Option<DateTime<Local>> {
    if let Some(dt) = parse_snapshot_name(expr) {
        return Some(dt);
    }
    if let Ok(naive) = NaiveDate::parse_from_str(expr, "%Y-%m-%d") {
        return Some(end_of_day(naive));
    }
    match expr {
        "now" | "today" => return Some(now),
        "yesterday" => return Some(end_of_day(now.date_naive() - Duration::days(1))),
        "last-week" => return Some(end_of_day(now.date_naive() - Duration::weeks(1))),
        "last-month" => {
            return now
                .date_naive()
                .checked_sub_months(chrono::Months::new(1))
                .map(end_of_day);
        }
        "last-year" => {
            return now
                .date_naive()
                .checked_sub_months(chrono::Months::new(12))
                .map(end_of_day);
        }
        _ => {}
    }
    if let Some(dt) = parse_relative(expr, now) {
        return Some(dt);
    }
    if let Some(rest) = expr.strip_prefix("last-")
        && let Some(wd) = weekday_from_str(rest)
    {
        return Some(most_recent_past(wd, now));
    }
    if let Some(wd) = weekday_from_str(expr) {
        return Some(most_recent_past(wd, now));
    }
    None
}

/// Find the newest snapshot at or before `target`.
fn find_nearest(snap_root: &Path, target: DateTime<Local>) -> Option<PathBuf> {
    let mut best: Option<(DateTime<Local>, PathBuf)> = None;
    for entry in fs::read_dir(snap_root).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name = name.to_str()?;
        if let Some(dt) = parse_snapshot_name(name)
            && dt <= target
            && best.as_ref().is_none_or(|(b, _)| dt > *b)
        {
            best = Some((dt, entry.path()));
        }
    }
    best.map(|(_, p)| p)
}

fn find_exact(snap_root: &Path, name: &str) -> Option<PathBuf> {
    let p = snap_root.join(name);
    if p.is_dir() { Some(p) } else { None }
}

/// Resolve a `/when` top-level component to a real directory on disk.
pub fn resolve(snap_root: &Path, expr: &str) -> Option<PathBuf> {
    let now = Local::now();
    if let Some(target) = resolve_target(expr, now) {
        return find_nearest(snap_root, target);
    }
    find_exact(snap_root, expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Local> {
        // A known Wednesday: 2026-08-19 12:00:00
        Local.with_ymd_and_hms(2026, 8, 19, 12, 0, 0).unwrap()
    }

    #[test]
    fn absolute_snapshot_name_roundtrips() {
        let dt = fixed_now();
        let name = format_snapshot_name(dt);
        let resolved = resolve_target(&name, fixed_now()).unwrap();
        assert_eq!(resolved, dt);
    }

    #[test]
    fn date_only_resolves_to_end_of_day() {
        let resolved = resolve_target("2026-08-01", fixed_now()).unwrap();
        assert_eq!(
            resolved.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-08-01 23:59:59"
        );
    }

    #[test]
    fn now_and_today_are_now() {
        let now = fixed_now();
        assert_eq!(resolve_target("now", now).unwrap(), now);
        assert_eq!(resolve_target("today", now).unwrap(), now);
    }

    #[test]
    fn yesterday_is_end_of_previous_day() {
        let resolved = resolve_target("yesterday", fixed_now()).unwrap();
        assert_eq!(
            resolved.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-08-18 23:59:59"
        );
    }

    #[test]
    fn relative_days_ago_subtracts_correctly() {
        let now = fixed_now();
        let resolved = resolve_target("3-days-ago", now).unwrap();
        assert_eq!(resolved, now - Duration::days(3));
    }

    #[test]
    fn relative_combined_short_form() {
        let now = fixed_now();
        assert_eq!(
            resolve_target("2h-ago", now).unwrap(),
            now - Duration::hours(2)
        );
        assert_eq!(
            resolve_target("30m-ago", now).unwrap(),
            now - Duration::minutes(30)
        );
    }

    #[test]
    fn last_month_goes_back_one_calendar_month() {
        let resolved = resolve_target("last-month", fixed_now()).unwrap();
        assert_eq!(resolved.format("%Y-%m-%d").to_string(), "2026-07-19");
    }

    #[test]
    fn bare_weekday_never_returns_today_even_if_it_matches() {
        // fixed_now() is a Wednesday; "wednesday" must go back a full week,
        // not resolve to today.
        let resolved = resolve_target("wednesday", fixed_now()).unwrap();
        assert_eq!(resolved.format("%Y-%m-%d").to_string(), "2026-08-12");
    }

    #[test]
    fn last_weekday_prefix_form_matches_bare_form() {
        let now = fixed_now();
        assert_eq!(
            resolve_target("last-tuesday", now),
            resolve_target("tuesday", now)
        );
    }

    #[test]
    fn unrecognized_expression_falls_through_to_none() {
        // callers use this to trigger the named-snapshot exact-match path
        assert_eq!(resolve_target("before-nginx-upgrade", fixed_now()), None);
    }

    #[test]
    fn find_nearest_picks_newest_at_or_before_target() {
        let dir = std::env::temp_dir().join(format!("whenfs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let earlier = Local.with_ymd_and_hms(2026, 8, 19, 10, 0, 0).unwrap();
        let later = Local.with_ymd_and_hms(2026, 8, 19, 11, 0, 0).unwrap();
        fs::create_dir(dir.join(format_snapshot_name(earlier))).unwrap();
        fs::create_dir(dir.join(format_snapshot_name(later))).unwrap();

        let target = Local.with_ymd_and_hms(2026, 8, 19, 10, 30, 0).unwrap();
        let found = find_nearest(&dir, target).unwrap();
        assert_eq!(
            found.file_name().unwrap().to_str().unwrap(),
            format_snapshot_name(earlier)
        );

        let target2 = Local.with_ymd_and_hms(2026, 8, 19, 12, 0, 0).unwrap();
        let found2 = find_nearest(&dir, target2).unwrap();
        assert_eq!(
            found2.file_name().unwrap().to_str().unwrap(),
            format_snapshot_name(later)
        );

        let target3 = Local.with_ymd_and_hms(2026, 8, 19, 9, 0, 0).unwrap();
        assert!(find_nearest(&dir, target3).is_none());

        let _ = fs::remove_dir_all(&dir);
    }
}
