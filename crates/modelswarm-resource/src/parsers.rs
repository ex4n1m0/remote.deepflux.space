//! Pure parsers for the Linux `/proc` sampling path. They live ungated so
//! their unit tests run on every OS (the Linux source itself only
//! compiles on Linux).

/// Parses `/proc/<pid>/stat` into `(ppid, utime_ticks, stime_ticks)`.
///
/// The comm field (2nd) is parenthesized and may contain spaces and
/// parentheses itself, so everything before the LAST `)` is skipped.
/// Remaining fields (1-based over the whole line): 3=state, 4=ppid, …,
/// 14=utime, 15=stime — i.e. after `state` and `ppid`, nine fields are
/// skipped, then utime and stime follow.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_proc_stat(line: &str) -> Option<(u32, u64, u64)> {
    let close = line.rfind(')')?;
    let mut fields = line[close + 1..].split_whitespace();
    let _state = fields.next()?;
    let ppid = fields.next()?.parse::<u32>().ok()?;
    for _ in 0..9 {
        fields.next()?; // pgrp, session, tty_nr, tpgid, flags, minflt, cminflt, majflt, cmajflt
    }
    let utime = fields.next()?.parse::<u64>().ok()?;
    let stime = fields.next()?.parse::<u64>().ok()?;
    Some((ppid, utime, stime))
}

/// Parses `/proc/<pid>/statm` into resident-set pages (2nd field).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_proc_statm_rss_pages(line: &str) -> Option<u64> {
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

/// Parses `/proc/meminfo` into `(MemTotal_kib, MemAvailable_kib)`.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_meminfo_kib(content: &str) -> Option<(u64, u64)> {
    let field = |key: &str| -> Option<u64> {
        content.lines().find_map(|l| {
            let rest = l.strip_prefix(key)?.strip_prefix(':')?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    };
    Some((field("MemTotal")?, field("MemAvailable")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_stat_basic_fields() {
        // utime=15, stime=20, ppid=1233
        let line = "1234 (llama-server) R 1233 1234 1234 0 -1 4194624 100 0 0 0 15 20 0 0 20 0 12 0 1000 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(parse_proc_stat(line), Some((1233, 15, 20)));
    }

    #[test]
    fn proc_stat_survives_spaces_and_parens_in_comm() {
        // comm "my (weird) name" with spaces: split at the LAST ')' only
        let line = "42 (my (weird) name) S 41 42 42 0 -1 4194624 5 0 0 0 1 2 0 0 20 0 1 0 1000 0 0";
        assert_eq!(parse_proc_stat(line), Some((41, 1, 2)));
    }

    #[test]
    fn proc_stat_rejects_truncated_lines() {
        // cut inside the fields between ppid and utime
        assert_eq!(parse_proc_stat("1 (init) S 0 1 1 0"), None);
        assert_eq!(parse_proc_stat("no parens at all"), None);
    }

    #[test]
    fn statm_rss_is_second_field() {
        assert_eq!(
            parse_proc_statm_rss_pages("1234 456 78 24 0 400 0"),
            Some(456)
        );
        assert_eq!(parse_proc_statm_rss_pages("1234"), None);
    }

    #[test]
    fn meminfo_total_and_available() {
        let content = "MemTotal:       32612345 kB\nMemFree:         1234567 kB\nMemAvailable:   20123456 kB\nBuffers:          234567 kB\n";
        assert_eq!(parse_meminfo_kib(content), Some((32_612_345, 20_123_456)));
        // MemAvailable missing on ancient kernels -> None (honest)
        assert_eq!(parse_meminfo_kib("MemTotal: 100 kB\n"), None);
    }
}
