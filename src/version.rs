//! Lenient version comparison for registries that only report "latest".
//!
//! Compares dot/dash-separated chunks: numeric chunks compare numerically,
//! other chunks compare lexically, numeric chunks sort after empty ones.
//! Pre-release-ish suffixes (`-rc1`, `-SNAPSHOT`) therefore sort below the
//! bare release, which is the right call for "is an update available".

use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq)]
enum Chunk<'a> {
    Num(u64),
    Str(&'a str),
}

fn chunks(v: &str) -> Vec<Chunk<'_>> {
    let mut out = Vec::new();
    for part in v.split(['.', '-', '_', '+']) {
        if part.is_empty() {
            continue;
        }
        // Split leading digits from the rest ("rc1" -> Str, "1" -> Num).
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.len() == part.len() {
            out.push(Chunk::Num(digits.parse::<u64>().unwrap_or(u64::MAX)));
        } else if !digits.is_empty() {
            out.push(Chunk::Num(digits.parse::<u64>().unwrap_or(u64::MAX)));
            out.push(Chunk::Str(&part[digits.len()..]));
        } else {
            out.push(Chunk::Str(part));
        }
    }
    out
}

fn cmp_chunk(a: &Chunk, b: &Chunk) -> Ordering {
    match (a, b) {
        (Chunk::Num(x), Chunk::Num(y)) => x.cmp(y),
        (Chunk::Str(x), Chunk::Str(y)) => x.cmp(y),
        // A numeric chunk beats a missing one; a string chunk (suffix like
        // "rc1"/"SNAPSHOT") sorts below "nothing" (the bare release).
        (Chunk::Num(_), Chunk::Str(_)) => Ordering::Greater,
        (Chunk::Str(_), Chunk::Num(_)) => Ordering::Less,
    }
}

/// Compare two version strings. Returns `Less` when `a` is older than `b`.
pub fn compare(a: &str, b: &str) -> Ordering {
    let (ac, bc) = (chunks(a), chunks(b));
    let common = ac.len().min(bc.len());
    for i in 0..common {
        match cmp_chunk(&ac[i], &bc[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    // All shared chunks equal: longer wins unless the extra chunks are all
    // string suffixes (pre-release markers sort below the release).
    let (longer, a_is_longer) = if ac.len() >= bc.len() {
        (&ac, true)
    } else {
        (&bc, false)
    };
    for chunk in &longer[common..] {
        match chunk {
            Chunk::Num(n) if *n == 0 => continue, // "1.2" == "1.2.0"
            Chunk::Num(_) => {
                return if a_is_longer {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            Chunk::Str(_) => {
                return if a_is_longer {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
        }
    }
    Ordering::Equal
}

/// True when `latest` is strictly newer than `current`.
pub fn is_newer(current: &str, latest: &str) -> bool {
    compare(current, latest) == Ordering::Less
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_comparison() {
        assert_eq!(compare("1.9.0", "1.10.0"), Ordering::Less);
        assert_eq!(compare("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(compare("2.0", "2.0.0"), Ordering::Equal);
        assert_eq!(compare("1.0.100", "1.0.229"), Ordering::Less);
        assert_eq!(compare("1.0.229", "1.0.229"), Ordering::Equal);
    }

    #[test]
    fn prerelease_sorts_below_release() {
        assert_eq!(compare("1.0.0-rc1", "1.0.0"), Ordering::Less);
        assert_eq!(compare("8.1.0", "8.2.0-alpha01"), Ordering::Less);
        assert_eq!(compare("1.2.3-SNAPSHOT", "1.2.3"), Ordering::Less);
    }

    #[test]
    fn android_style_versions() {
        assert!(is_newer("1.9.0", "1.12.0"));
        assert!(!is_newer("1.12.0", "1.9.0"));
        assert!(!is_newer("1.12.0", "1.12.0"));
        assert!(is_newer("20201201", "20260101"));
    }
}
