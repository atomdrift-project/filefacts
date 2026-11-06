use super::*;
use crate::formats::source::parse::PARSE_WORK_OVERRIDE;
fn calls(source: &[u8]) -> Vec<String> {
    let mut values = Values::default();
    extract(source, &mut values);
    values
        .get("media.php.request_calls")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
#[test]
fn embedded_php_request_calls_bind_the_first_argument() {
    for source in [
        &b"GIF89a\x00\xff<?php system($_GET['cmd']); ?>"[..],
        b"GIF89a<?= system($_REQUEST['cmd']); ?>",
        b"GIF89a<?PHP /* note */ $label='status'; SyStEm(($_COOKIE['cmd'])); ?>",
        b"GIF89a<?php \\system($_POST['cmd']); ?>",
    ] {
        assert_eq!(calls(source), ["system"], "{source:?}");
    }
    assert_eq!(calls(b"GIF89a<?php eval($_POST['code']); ?>"), ["eval"]);
}
#[test]
fn embedded_php_request_calls_ignore_non_calls_and_other_arguments() {
    for source in [
        &b"GIF89a<?php echo 'system($_GET[\"cmd\"]);'; ?>"[..],
        b"GIF89a<?php /* system($_GET['cmd']); */ echo 1; ?>",
        b"GIF89a<?php $mode=$_GET['mode']; system('date'); ?>",
        b"GIF89a<?php system('date', $_GET['cmd']); ?>",
        b"GIF89a<?php $object->system($_GET['cmd']); ?>",
        b"GIF89a<?php Type::system($_GET['cmd']); ?>",
        b"GIF89a<?php system($_get['cmd']); ?>",
        b"GIF89a<?php echo 1; ?> system($_GET['cmd']);",
        b"GIF89a<?phpNotCode system($_GET['cmd']); ?>",
        b"GIF89a<?php namespace Local { system($_GET['cmd']); } ?>",
        b"GIF89a<?php namespace Local; system($_GET['cmd']); ?>",
    ] {
        assert!(calls(source).is_empty(), "{source:?}");
    }
}
#[test]
fn embedded_php_gif_comment_request_command() {
    for tag in ["<?php ", "<?PHP\n", "<?="] {
        let payload = format!("{tag}system($_REQUEST[\"task\"]); ?>");
        let mut source = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff\x21\xfe".to_vec();
        source.push(payload.len() as u8);
        source.extend_from_slice(payload.as_bytes());
        source.extend_from_slice(b"\0\x2c\0\0\0\0\x01\0\x01\0\0\x02\x02\x44\x01\0\x3b");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert_eq!(calls(&source), ["system"], "{}", tree.root_node().to_sexp());
    }
}

#[test]
fn embedded_php_byte_budget_is_explicit() {
    let mut source = vec![b' '; MAX_BYTES + 1];
    source[..3].copy_from_slice(b"<?=");
    let mut values = Values::default();
    extract(&source, &mut values);
    assert_eq!(
        values.get("media.php.analysis_limited"),
        Some(&Value::Bool(true))
    );
    assert!(values.get("media.php.request_calls").is_none());
}

/// The parse runs under the shared, load-independent source parse budget,
/// so its outcome, which the content-keyed cache stores, never depends on
/// how busy the machine is.
#[test]
fn embedded_php_parse_uses_the_shared_work_budget() {
    let source = format!(
        "GIF89a<?php {} system($_GET['cmd']); ?>",
        "$a = 1;".repeat(2_000)
    );
    PARSE_WORK_OVERRIDE.set(1);
    let mut values = Values::default();
    extract(source.as_bytes(), &mut values);
    PARSE_WORK_OVERRIDE.set(0);
    assert_eq!(
        values.get("media.php.analysis_limited"),
        Some(&Value::Bool(true))
    );
    assert!(values.get("media.php.request_calls").is_none());
}
/// `<?=` turns up by chance in a few percent of compressed media; a tag the
/// interpreter could run is followed by code, so a tag followed by binary
/// bytes starts no parse, and the real tag after such a decoy is still read.
#[test]
fn a_tag_followed_by_binary_bytes_starts_no_parse() {
    let mut media = b"\xff\xd8\xff\xe0".to_vec();
    media.extend((0..20_000_u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8 | 0x80));
    media.extend_from_slice(b"<?=\x8f\x00\x13\xc4\x01\xfe\x7f\x02");
    media.extend((0..20_000_u32).map(|i| (i.wrapping_mul(40_503) >> 7) as u8 | 0x80));
    let before = crate::formats::source::parse::PARSES.get();
    let mut values = Values::default();
    extract(&media, &mut values);
    assert_eq!(crate::formats::source::parse::PARSES.get(), before);
    assert!(values.get("media.php.request_calls").is_none());

    media.extend_from_slice(b"<?php system($_GET['c']); ?>");
    assert_eq!(calls(&media), ["system"]);
}
