//! PHP's tag delimiters, which decide whether bytes can be PHP at all: code
//! only runs between `<?`/`<?php`/`<?=` and `?>`.

use super::heuristics::SCAN_LIMIT;

/// `true` when the bytes carry a PHP tag delimiter — an opening `<?`, `<?php`,
/// or `<?=`, or the `?>` that closes a fragment whose opening tag was cut off.
/// `<?xml …?>` is an XML processing instruction and never counts on its own.
pub(super) fn has_php_tag(data: &[u8]) -> bool {
    let mut saw_non_php_open = false;
    let mut rest = data;
    let limit = data.len().min(SCAN_LIMIT * 2);
    let mut examined = 0;
    // Bound the tag search, but inspect the original suffix. Cutting the
    // sample through a Java type name must not turn its wildcard into PHP.
    while examined < limit {
        let search_len = rest.len().min(limit - examined + 1);
        let Some(pos) = memchr::memmem::find(rest.get(..search_len).unwrap_or(rest), b"<?") else {
            break;
        };
        let Some(after) = rest.get(pos + 2..) else {
            break;
        };
        let bound = after.get(..512).unwrap_or(after).trim_ascii_start();
        // Java wildcard bounds in API signature catalogs are not PHP short
        // tags. Nor is Class<?>: its question mark is generic type syntax.
        // These cannot begin valid PHP statements. Continue searching so a
        // genuine tag later in a mixed file still establishes PHP content.
        let java_wildcard = after.starts_with(b">")
            || (after.first().is_some_and(u8::is_ascii_whitespace)
                && [b"extends".as_slice(), b"super".as_slice()]
                    .iter()
                    .any(|keyword| {
                        if !bound.starts_with(keyword)
                            || !bound
                                .get(keyword.len())
                                .is_some_and(u8::is_ascii_whitespace)
                        {
                            return false;
                        }
                        let Some(name) = bound.get(keyword.len()..) else {
                            return false;
                        };
                        let name = name.trim_ascii_start();
                        let valid_start = name.first().is_some_and(|b| {
                            b.is_ascii_alphabetic() || matches!(*b, b'_' | b'$') || *b >= 0x80
                        });
                        let length = name
                            .iter()
                            .take(512)
                            .take_while(|b| {
                                b.is_ascii_alphanumeric()
                                    || matches!(**b, b'_' | b'$' | b'.')
                                    || **b >= 0x80
                            })
                            .count();
                        // PHP word operators followed by arrays or variables
                        // can resemble Java type suffixes. Keep PHP for those
                        // ambiguous names rather than hiding executable input.
                        let Some((prefix, suffix)) = name.split_at_checked(length) else {
                            return false;
                        };
                        let first = prefix
                            .split(|b| matches!(*b, b'.' | b'$'))
                            .next()
                            .unwrap_or_default();
                        let php_operator = [b"and".as_slice(), b"or", b"xor", b"instanceof"]
                            .iter()
                            .any(|op| first.eq_ignore_ascii_case(op));
                        valid_start
                            && !php_operator
                            && suffix
                                .trim_ascii_start()
                                .first()
                                .is_some_and(|b| matches!(*b, b'>' | b'<' | b'['))
                    }));
        if after
            .get(..3)
            .is_some_and(|pi| pi.eq_ignore_ascii_case(b"xml"))
            || java_wildcard
        {
            saw_non_php_open = true;
        } else {
            return true;
        }
        examined += pos + 2;
        rest = after;
    }
    !saw_non_php_open && memchr::memmem::find(data.get(..limit).unwrap_or(data), b"?>").is_some()
}
