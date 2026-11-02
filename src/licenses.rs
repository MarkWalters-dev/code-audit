//! License compliance: SPDX normalization, fingerprinting, policy.
//!
//! Each ecosystem reports its dependencies' licenses (crate metadata,
//! PyPI classifiers, npm `license`, Go module LICENSE files, Maven POM
//! `<licenses>`); this module normalizes free-text names to SPDX ids,
//! classifies full license texts by fingerprint, and checks the result
//! against the `[licenses] deny` policy. Unknown licenses are always
//! reported, never silently passed: an unaudited license is itself a
//! compliance finding.

use crate::ecosystem::{Ctx, Notice, NoticeCheck};

/// Policy from `[licenses]`: denied SPDX ids (family prefixes match, so
/// `deny = ["GPL"]` catches every GPL variant) — comparison is
/// case-insensitive.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub deny: Vec<String>,
}

impl Policy {
    pub fn from_config(deny: Option<Vec<String>>) -> Self {
        let deny = deny
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.trim().to_uppercase())
            .filter(|d| !d.is_empty())
            .collect();
        Self { deny }
    }

    fn hit(&self, license: &str) -> bool {
        let core = license_core(license);
        self.deny.iter().any(|d| {
            let want = license_core(d);
            core == want
                || core.starts_with(&format!("{want}-"))
                || core.starts_with(&format!("{want}."))
        })
    }
}

/// Comparison core of an SPDX id: uppercased, `-only`/`-or-later` suffix
/// folded away so `GPL-3.0` matches every GPL 3 variant.
fn license_core(id: &str) -> String {
    let upper = id.trim().to_uppercase();
    upper
        .strip_suffix("-ONLY")
        .or_else(|| upper.strip_suffix("-OR-LATER"))
        .unwrap_or(&upper)
        .to_string()
}

/// License/policy notices for one dependency: one per denied license, or
/// a single unknown-license notice when nothing could be determined.
pub fn license_notices(
    policy: &Policy,
    name: &str,
    version: &str,
    licenses: &[String],
) -> Vec<Notice> {
    if licenses.is_empty() {
        return vec![Notice {
            check: NoticeCheck::Licenses,
            name: name.to_string(),
            message: format!("{version}: license could not be determined"),
            file: None,
            line: None,
        }];
    }
    licenses
        .iter()
        .filter(|l| policy.hit(l))
        .map(|l| Notice {
            check: NoticeCheck::Licenses,
            name: name.to_string(),
            message: format!("{version}: {l} is denied by [licenses] deny"),
            file: None,
            line: None,
        })
        .collect()
}

/// Relicensing notice when the newest release carries a different license
/// set than the used version. Both ends must be known — an empty set on
/// either side stays silent (the used side already gets its own unknown
/// notice). Comparison is order-insensitive over normalized ids.
pub fn license_change(
    name: &str,
    latest: &str,
    before: &[String],
    after: &[String],
) -> Option<Notice> {
    if before.is_empty() || after.is_empty() {
        return None;
    }
    let mut a = before.to_vec();
    let mut b = after.to_vec();
    a.sort();
    b.sort();
    if a == b {
        return None;
    }
    Some(Notice {
        check: NoticeCheck::LicenseChange,
        name: name.to_string(),
        message: format!(
            "{latest} changes license: {} -> {}",
            a.join(" + "),
            b.join(" + ")
        ),
        file: None,
        line: None,
    })
}

/// Normalize free-text license names to SPDX ids. Handles SPDX
/// expressions (`MIT OR Apache-2.0`, `GPL-2.0-only WITH ...`), PyPI
/// classifier segments, POM `<name>` values, and npm `license` strings.
/// Unrecognized text yields nothing (unknown), except single plausible
/// tokens (`UNLICENSED`, custom names), which pass through for policy
/// matching.
pub fn normalize_spdx(text: &str) -> Vec<String> {
    // Whole-string match first: some names (`BSD 3-Clause "New" or
    // "Revised"`) contain operator words.
    let clean = strip_parens(text);
    if clean.is_empty() {
        return Vec::new();
    }
    if let Some(id) = lookup_name(clean) {
        return vec![id.to_string()];
    }
    let mut out = Vec::new();
    for part in split_expression(clean) {
        // Split fragments carry unbalanced halves (`(GPL-2.0-only`),
        // so trim parens aggressively here.
        let piece = part.trim().trim_matches(|c| c == '(' || c == ')').trim();
        if piece.is_empty() {
            continue;
        }
        // `GPL-2.0-only WITH Classpath-exception-2.0`: the base id drives
        // policy; modeling exceptions is out of scope (see README).
        let base = piece
            .split_once(" WITH ")
            .or_else(|| piece.split_once(" with "))
            .map(|(b, _)| b.trim())
            .unwrap_or(piece);
        if let Some(id) = lookup_name(base) {
            push_unique(&mut out, id.to_string());
        } else if is_token(base) {
            push_unique(&mut out, base.to_string());
        }
    }
    out
}

/// Strip one balanced outer paren layer: `(MIT)` becomes `MIT`, while
/// `v3 (GPLv3)` (unbalanced ends) is left intact.
fn strip_parens(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('(') && t.ends_with(')') {
        t[1..t.len() - 1].trim()
    } else {
        t
    }
}

/// Split an SPDX expression on OR/AND (either case). Parens do not
/// matter: every mentioned id is collected for policy matching.
fn split_expression(text: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let rest: String = chars[i..].iter().collect();
        let upper = rest.to_uppercase();
        if upper.starts_with(" OR ") {
            parts.push(String::new());
            i += 4;
        } else if upper.starts_with(" AND ") {
            parts.push(String::new());
            i += 5;
        } else {
            parts.last_mut().unwrap().push(chars[i]);
            i += 1;
        }
    }
    parts
}

/// Free-text name to SPDX id (case-insensitive). Generic family names map
/// to their de-facto-standard member (documented approximation).
fn lookup_name(name: &str) -> Option<&'static str> {
    Some(match name.to_uppercase().replace('_', "-").as_str() {
        "MIT" | "MIT LICENSE" | "THE MIT LICENSE (MIT)" | "MIT LICENSED" | "EXPAT" => "MIT",
        "APACHE-2.0"
        | "APACHE LICENSE 2.0"
        | "APACHE LICENSE, VERSION 2.0"
        | "APACHE LICENSE VERSION 2.0"
        | "APACHE SOFTWARE LICENSE"
        | "THE APACHE SOFTWARE LICENSE, VERSION 2.0"
        | "THE APACHE LICENSE, VERSION 2.0"
        | "APACHE LICENSE (2.0)" => "Apache-2.0",
        "BSD"
        | "BSD LICENSE"
        | "BSD-3-CLAUSE"
        | "BSD 3-CLAUSE \"NEW\" OR \"REVISED\" LICENSE"
        | "3-CLAUSE BSD LICENSE"
        | "NEW BSD"
        | "BSD-3-CLAUSE-NEW" => "BSD-3-Clause",
        "BSD-2-CLAUSE"
        | "BSD 2-CLAUSE \"SIMPLIFIED\" LICENSE"
        | "2-CLAUSE BSD LICENSE"
        | "SIMPLIFIED BSD"
        | "FREEBSD" => "BSD-2-Clause",
        "ISC" | "ISC LICENSE (ISCL)" | "ISC LICENSE" => "ISC",
        "BLUEOAK-1.0.0" | "BLUE OAK MODEL LICENSE 1.0.0" | "BLUEOAK" => "BlueOak-1.0.0",
        "BUSL-1.1" | "BUSL" => "BUSL-1.1",
        "SSPL-1.0" | "SSPL" | "SERVER SIDE PUBLIC LICENSE" => "SSPL-1.0",
        "ELASTIC-2.0" | "ELASTIC LICENSE 2.0" | "ELASTIC LICENSE V2" => "Elastic-2.0",
        "RSALV2" | "RSAL-2.0" | "REDIS SOURCE AVAILABLE LICENSE 2.0" => "RSAL-2.0",
        "GPL-3.0-ONLY"
        | "GPLV3"
        | "GNU GENERAL PUBLIC LICENSE V3 (GPLV3)"
        | "GNU GENERAL PUBLIC LICENSE VERSION 3" => "GPL-3.0-only",
        "GPL-3.0-OR-LATER"
        | "GPLV3+"
        | "GNU GENERAL PUBLIC LICENSE V2 OR LATER (GPLV2+)"
        | "GPL-3.0" => "GPL-3.0-or-later",
        "GPL-2.0-ONLY"
        | "GPLV2"
        | "GNU GENERAL PUBLIC LICENSE V2 (GPLV2)"
        | "GNU GENERAL PUBLIC LICENSE VERSION 2" => "GPL-2.0-only",
        "GPL-2.0-OR-LATER" | "GPLV2+" | "GPL-2.0" => "GPL-2.0-or-later",
        "GPL" => "GPL-3.0-or-later",
        "LGPL-3.0-ONLY" | "GNU LESSER GENERAL PUBLIC LICENSE V3 (LGPLV3)" => "LGPL-3.0-only",
        "LGPL-3.0-OR-LATER" | "LGPL-3.0" => "LGPL-3.0-or-later",
        "LGPL-2.1-ONLY" | "GNU LESSER GENERAL PUBLIC LICENSE V2.1 (LGPLV2.1)" => "LGPL-2.1-only",
        "LGPL-2.1-OR-LATER" | "LGPL-2.1" | "LGPL" => "LGPL-2.1-or-later",
        "AGPL-3.0-ONLY" | "GNU AFFERO GENERAL PUBLIC LICENSE V3" => "AGPL-3.0-only",
        "AGPL-3.0-OR-LATER" | "AGPL-3.0" | "AGPL" => "AGPL-3.0-or-later",
        "MPL-2.0" | "MOZILLA PUBLIC LICENSE 2.0 (MPL 2.0)" | "MPL" => "MPL-2.0",
        "EPL-2.0" | "ECLIPSE PUBLIC LICENSE 2.0" | "ECLIPSE PUBLIC LICENSE V. 2.0" | "EPL" => {
            "EPL-2.0"
        }
        "EPL-1.0" | "ECLIPSE PUBLIC LICENSE 1.0" | "ECLIPSE PUBLIC LICENSE V. 1.0" => "EPL-1.0",
        "GNU GENERAL PUBLIC LICENSE, VERSION 2 WITH THE GNU CLASSPATH EXCEPTION" => "GPL-2.0-only",
        "UNLICENSE" | "THE UNLICENSE" => "Unlicense",
        "CC0-1.0" | "CC0 1.0 UNIVERSAL" => "CC0-1.0",
        "ZLIB" | "ZLIB/LIBPNG LICENSE" => "Zlib",
        "ARTISTIC-2.0" | "ARTISTIC LICENSE 2.0" => "Artistic-2.0",
        "PSF-2.0" | "PYTHON SOFTWARE FOUNDATION LICENSE" => "PSF-2.0",
        "0BSD" | "BSD ZERO CLAUSE LICENSE" => "0BSD",
        "WTFPL" | "DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE" => "WTFPL",
        _ => return None,
    })
}

/// A single plausible token (no spaces): kept verbatim for policy
/// matching (`UNLICENSED`, custom names). Sentences are not tokens.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '/' | ':'))
}

/// Classify full license file texts by fingerprint (Go module zips carry
/// no metadata, only files). Every match is reported: dual-licensed
/// texts match twice.
pub fn classify_license_text(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut out = Vec::new();
    if lower.contains("apache license") && lower.contains("version 2.0") {
        out.push("Apache-2.0".to_string());
    }
    if lower.contains("mit license") {
        out.push("MIT".to_string());
    }
    if lower.contains("isc license") {
        out.push("ISC".to_string());
    }
    if lower.contains("mozilla public license") && lower.contains("version 2.0") {
        out.push("MPL-2.0".to_string());
    }
    if lower.contains("eclipse public license") {
        if lower.contains("2.0") {
            out.push("EPL-2.0".to_string());
        } else {
            out.push("EPL-1.0".to_string());
        }
    }
    if lower.contains("server side public license") {
        out.push("SSPL-1.0".to_string());
    }
    if lower.contains("elastic license") && lower.contains("2.0") {
        out.push("Elastic-2.0".to_string());
    }
    if lower.contains("gnu affero general public license") {
        gpl_variant(&lower, "AGPL-3.0", &mut out);
    } else if lower.contains("gnu lesser general public license") {
        if lower.contains("version 3") {
            gpl_variant(&lower, "LGPL-3.0", &mut out);
        } else {
            gpl_variant(&lower, "LGPL-2.1", &mut out);
        }
    } else if lower.contains("gnu general public license") {
        if lower.contains("version 3") {
            gpl_variant(&lower, "GPL-3.0", &mut out);
        } else {
            gpl_variant(&lower, "GPL-2.0", &mut out);
        }
    }
    if lower.contains("redistribution and use in source and binary forms") {
        // The "neither the name" clause is what makes it 3-clause.
        if lower.contains("neither the name") {
            out.push("BSD-3-Clause".to_string());
        } else {
            out.push("BSD-2-Clause".to_string());
        }
    }
    if lower.contains("do what the fuck you want") {
        out.push("WTFPL".to_string());
    }
    if lower.contains("this is free and unencumbered software") {
        out.push("Unlicense".to_string());
    }
    out
}

fn gpl_variant(lower: &str, family: &str, out: &mut Vec<String>) {
    if lower.contains("or (at your option) any later version") {
        out.push(format!("{family}-or-later"));
    } else {
        out.push(format!("{family}-only"));
    }
}

fn push_unique(out: &mut Vec<String>, id: String) {
    if !out.contains(&id) {
        out.push(id);
    }
}

// ---------------------------------------------------------------------------
// Framework end-of-life
// ---------------------------------------------------------------------------

/// Dependencies that are really frameworks with endoflife.date coverage:
/// (ecosystem, dependency lowercase, product id). Unknown products 404
/// and are skipped, so this map can be generous.
const FRAMEWORKS: &[(&str, &str, &str)] = &[
    ("python", "django", "django"),
    ("node", "react", "react"),
    ("node", "react-dom", "react"),
    ("node", "@angular/core", "angular"),
    ("node", "angular", "angularjs"),
    ("node", "vue", "vue"),
    ("node", "next", "nextjs"),
    ("node", "nuxt", "nuxt"),
];

/// End-of-life notice when a framework dependency's cycle is past EOL.
pub fn eol_notice(ctx: &Ctx, eco: &str, name: &str, version: &str) -> Option<Notice> {
    let lower = name.to_lowercase();
    let product = FRAMEWORKS
        .iter()
        .find(|(e, n, _)| *e == eco && *n == lower)
        .map(|(_, _, p)| *p)?;
    match crate::toolchains::product_eol(&ctx.cache, product, version) {
        Some(Some(date)) => Some(Notice {
            check: NoticeCheck::Eol,
            name: name.to_string(),
            message: format!("{version} is end-of-life since {date}"),
            file: None,
            line: None,
        }),
        Some(None) => Some(Notice {
            check: NoticeCheck::Eol,
            name: name.to_string(),
            message: format!("{version} is end-of-life"),
            file: None,
            line: None,
        }),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_names_and_expressions() {
        assert_eq!(normalize_spdx("MIT"), vec!["MIT".to_string()]);
        assert_eq!(normalize_spdx("MIT License"), vec!["MIT".to_string()]);
        assert_eq!(
            normalize_spdx("MIT OR Apache-2.0"),
            vec!["MIT".to_string(), "Apache-2.0".to_string()]
        );
        assert_eq!(
            normalize_spdx("(GPL-2.0-only OR MIT) AND Apache-2.0"),
            vec![
                "GPL-2.0-only".to_string(),
                "MIT".to_string(),
                "Apache-2.0".to_string()
            ]
        );
        assert_eq!(
            normalize_spdx("Apache License, Version 2.0"),
            vec!["Apache-2.0".to_string()]
        );
        assert_eq!(
            normalize_spdx("GNU General Public License v3 (GPLv3)"),
            vec!["GPL-3.0-only".to_string()]
        );
        assert_eq!(
            normalize_spdx("GPL-2.0-only WITH Classpath-exception-2.0"),
            vec!["GPL-2.0-only".to_string()]
        );
        assert_eq!(
            normalize_spdx("BSD 3-Clause \"New\" or \"Revised\" License"),
            vec!["BSD-3-Clause".to_string()]
        );
        // Maven POM `<name>` strings seen in the wild.
        assert_eq!(
            normalize_spdx("The Apache Software License, Version 2.0"),
            vec!["Apache-2.0".to_string()]
        );
        assert_eq!(
            normalize_spdx("Eclipse Public License v. 1.0"),
            vec!["EPL-1.0".to_string()]
        );
        assert_eq!(
            normalize_spdx(
                "GNU General Public License, version 2 with the GNU Classpath Exception"
            ),
            vec!["GPL-2.0-only".to_string()]
        );
        // Source-available / relicense-era ids.
        assert_eq!(
            normalize_spdx("BlueOak-1.0.0"),
            vec!["BlueOak-1.0.0".to_string()]
        );
        assert_eq!(normalize_spdx("BUSL"), vec!["BUSL-1.1".to_string()]);
        assert_eq!(normalize_spdx("SSPL"), vec!["SSPL-1.0".to_string()]);
        assert_eq!(
            normalize_spdx("Elastic License 2.0"),
            vec!["Elastic-2.0".to_string()]
        );
        // Custom tokens pass through for policy matching; prose does not.
        assert_eq!(normalize_spdx("UNLICENSED"), vec!["UNLICENSED".to_string()]);
        assert!(normalize_spdx("SEE LICENSE IN LICENSE").is_empty());
        assert!(normalize_spdx("").is_empty());
    }

    #[test]
    fn classifies_license_texts() {
        let mit = "MIT License\n\nCopyright (c) 2024\n\nPermission is hereby granted...";
        assert_eq!(classify_license_text(mit), vec!["MIT".to_string()]);
        let apache = "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/";
        assert_eq!(
            classify_license_text(apache),
            vec!["Apache-2.0".to_string()]
        );
        let gpl = "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007. ... or (at your option) any later version ...";
        assert_eq!(
            classify_license_text(gpl),
            vec!["GPL-3.0-or-later".to_string()]
        );
        let bsd3 = "Redistribution and use in source and binary forms ... Neither the name of the copyright holder ...";
        assert_eq!(
            classify_license_text(bsd3),
            vec!["BSD-3-Clause".to_string()]
        );
        let bsd2 = "Redistribution and use in source and binary forms, with or without modification, are permitted ... THIS SOFTWARE IS PROVIDED ...";
        assert_eq!(
            classify_license_text(bsd2),
            vec!["BSD-2-Clause".to_string()]
        );
        assert!(classify_license_text("all rights reserved, bespoke terms").is_empty());
    }

    #[test]
    fn policy_matches_families() {
        let policy = Policy::from_config(Some(vec!["GPL".to_string(), "agpl-3.0".to_string()]));
        assert!(policy.hit("GPL-3.0-only"));
        assert!(policy.hit("GPL-2.0-or-later"));
        assert!(policy.hit("AGPL-3.0-ONLY"));
        assert!(!policy.hit("MIT"));
        assert!(!policy.hit("LGPL-3.0-only"));
        // Unknown licenses always surface.
        let notices = license_notices(&policy, "foo", "1.0", &[]);
        assert_eq!(notices.len(), 1);
        assert!(notices[0].message.contains("could not be determined"));
        let notices = license_notices(&policy, "foo", "1.0", &["MIT".to_string()]);
        assert!(notices.is_empty());
        let notices = license_notices(&policy, "foo", "1.0", &["GPL-3.0-only".to_string()]);
        assert_eq!(notices.len(), 1);
        assert!(notices[0].message.contains("denied"));
    }

    #[test]
    fn change_needs_two_known_differing_sets() {
        let before = vec!["Apache-2.0".to_string()];
        let after = vec!["Elastic-2.0".to_string()];
        let n = license_change("elasticsearch", "8.0.0", &before, &after).unwrap();
        assert_eq!(n.check, NoticeCheck::LicenseChange);
        assert_eq!(
            n.message,
            "8.0.0 changes license: Apache-2.0 -> Elastic-2.0"
        );
        // Same sets (any order), or unknown on either side: silent.
        let same = vec!["MIT".to_string(), "Apache-2.0".to_string()];
        let reordered = vec!["Apache-2.0".to_string(), "MIT".to_string()];
        assert!(license_change("x", "2.0", &same, &reordered).is_none());
        assert!(license_change("x", "2.0", &[], &after).is_none());
        assert!(license_change("x", "2.0", &before, &[]).is_none());
    }
}
