use super::*;
use serde_json::json;

fn parse(bytes: &[u8]) -> Values {
    let mut values = Values::default();
    let mut errors = Errors::new();
    extract(bytes, &mut values, &mut errors);
    values
}

#[test]
fn sections_lists_and_actions() {
    // A realistic benign launcher (RustDesk).
    let values = parse(
        br"[Desktop Entry]
Name=RustDesk
GenericName=Remote Desktop
Exec=rustdesk %u
Icon=rustdesk
Terminal=false
Type=Application
Categories=Network;RemoteAccess;GTK;
Actions=new-window;

[Desktop Action new-window]
Name=Open a New Window
Exec=rustdesk %u
",
    );
    assert_eq!(
        values.get("desktop_entry.exec"),
        Some(&json!("rustdesk %u"))
    );
    assert_eq!(
        values.get("desktop_entry.type"),
        Some(&json!("Application"))
    );
    assert_eq!(values.get("desktop_entry.terminal"), Some(&json!("false")));
    // `;`-separated list keys become arrays.
    assert_eq!(
        values.get("desktop_entry.categories"),
        Some(&json!(["Network", "RemoteAccess", "GTK"]))
    );
    // A secondary section is its own snake_case root.
    assert_eq!(
        values.get("desktop_action_new_window.exec"),
        Some(&json!("rustdesk %u"))
    );
}

#[test]
fn autostart_dropper_keeps_every_signal() {
    // Modeled on the APT36 weaponized autostart `.desktop` dropper: an inline
    // `bash -c` base64 stage, GNOME autostart, a root KDE hint and a PDF icon.
    let values = parse(
        br#"
# fake embedded thumbnail data
[Desktop Entry]
Name=Contract_for_Procurement
Exec=bash -c 'f(){ echo "$1"|base64 -d|xxd -r -p|base64 -d; }; p="/tmp/.a-$(date +%s%N|md5sum|cut -c1-8)"; v="$(f NTQ0NT==)"; (eval "$v" > "$p" 2>/dev/null && chmod +x "$p" 2>/dev/null && "$p") &'
Terminal=false
Type=Application
Icon=application-pdf
X-GNOME-Autostart-enabled=true
X-KDE-Username=root
"#,
    );
    let exec = values
        .get("desktop_entry.exec")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    for needle in ["bash -c", "base64 -d", "eval", "chmod +x"] {
        assert!(exec.contains(needle), "{needle} missing from {exec}");
    }
    assert_eq!(
        values.get("desktop_entry.x_gnome_autostart_enabled"),
        Some(&json!("true"))
    );
    assert_eq!(
        values.get("desktop_entry.x_kde_username"),
        Some(&json!("root"))
    );
    assert_eq!(
        values.get("desktop_entry.icon"),
        Some(&json!("application-pdf"))
    );
}

#[test]
fn localized_keys_are_dropped() {
    let values = parse(b"[Desktop Entry]\nName=Editor\nName[cs]=Editor CS\nName[de]=Editor DE\n");
    assert_eq!(values.get("desktop_entry.name"), Some(&json!("Editor")));
}

#[test]
fn escaped_semicolon_stays_in_its_list_item() {
    let values = parse(b"[Desktop Entry]\nKeywords=one;two\\;still-two;three;\n");
    assert_eq!(
        values.get("desktop_entry.keywords"),
        Some(&json!(["one", "two;still-two", "three"]))
    );
}
