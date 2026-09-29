# CFML static-analysis fixtures

These are malicious templates retained for static parsing only. Never execute them.

- `datasource_shell.cfm`: original sample `987de3c74aaa5371c98365b281fdc3c4b680558aae5b4c9895ec6b8c9fc083d2`, from the triage corpus. Command execution and datasource credential decryption/disclosure. The cfexecute tag starts at byte 878.
- `encrypted_shell_decoded.cfm`: independently decoded Allaire template from original `c28894e4ab24` (full original hash/path in the review cohort). Plaintext SHA-256 `110db2340e0aecb5c59d73b15617b28999d941f974ae04acf4d53ddcf945e9dc`, 20,626 bytes. Password-protected command/file manager plus pre-login URL callback. The cfexecute tag starts at byte 12558; all 332 CFML opening/closing tags were accounted for.

Decode/source review: `/var/tmp/triage40/review/cfml-review/README.md`.
The syntax-layer unit tests assert both fixture hashes and command-tag offsets.
The bounded tag producer populates public tag-call symbols and Flow. Original encrypted bytes explicitly report unavailable encrypted syntax; callers such as Cleave decode and open the plaintext separately. Script-local bindings, tag function bodies and unsupported expressions remain explicit limitations. Cleave member-origin matching is integrated.

Expression regressions retain call arguments and receivers separately, support concatenation and parentheses, and recover the decoded shell's Java request-parameter chain and Replace-based write path. Calls remain opaque unless the consumer supplies an explicit transfer model. Tests cover quoted delimiters, malformed/truncated expressions, width/depth limits, wrong fields, and transfer argument selection. This remains source-local may-flow evidence rather than runtime reachability or complete CFML interpretation.

Expression calls also appear in public Symbols, with byte offsets, positional argument shapes, and literal values matching their Flow nodes. Tests check this correspondence and the original shell's Encrypt argument provenance; apparent calls inside comments and quoted source text are excluded. Indexed literal member names are canonicalized to dotted paths, with dynamic indexes represented by [*].

`encrypted_shell_original.cfm` retains the original encrypted specimen so ciphertext is never interpreted as tag source.

`implicit_command_shell.cmf` is the original guarded cmd.exe shell, SHA-256 `29777403e2f3cd010ff179b71233137fe75379b0fc3b7f7b2932bb6af94a0dd9`. A regression traces the unscoped command argument inside its positive Form existence guard. Such implicit resolution is marked runtime-dependent; explicit disabling, local shadowing, negative guards and explicit Variables reads are tested separately.

Script-boundary regressions now assert that datasource_shell.cfm retains its script body range and the closing CFOUTPUT afterward. Tag scanning resumes after script blocks while strings/comments remain opaque; CFScript calls now have bounded lexical extraction with original offsets; script-local assignments and control-flow relationships remain unavailable.

The retained datasource shell has assertions for CreateObject, its datasource-service call chain, and Decrypt argument zero reading datasourceobb[*].password. Synthetic tests cover comment masking, inline comments, call nesting/count limits, function signature exclusion, malformed indexing, and known member overwrites.

Conditional-call regressions verify the decoded shell's IsDefined(session.in) argument and source offset. Calls in CFIF/CFELSEIF headers are extracted independently of condition truth; ELSEIF uses restored entry bindings rather than sibling assignments.

CFSET assignment regressions check `Symbol::Bind` target normalization, original
source offsets, and syntactic RHS shape (an alias to a string remains an
identifier). Literal `##` and interpolated `#value#` are distinguished. Simple
CFIF/CFELSEIF inequalities expose tag-call arguments `[left identifier, "neq",
right identifier]`; `!=` is normalized to `neq`. These observations do not assert
truth, reachability, variable identity across nearby statements, or authentication.
Quoted/commented comparisons and unsupported compound expressions are excluded.
The retained decoded shell supplies the password-binding/comparison regression.

Unquoted ordinary tag attributes are tested as literal/interpolated text, like
quoted attributes; CFSET RHS remains expression syntax. Regressions distinguish
`name=form.command` from `name=#form.command#`, keep bare action names literal
when a same-named variable exists, and cover alias interpolation, concatenation,
escaped hashes, exact offsets and every source prefix. The retained decoded
shell's directory-create call must contain both Form.dir and Form.cr_dir origins.
Semantics reference: https://guides.adobe.com/coldfusion/en/docs/develop-coldfusion-applications/the-cfml-programming-language/using-number-signs.html

Mixed markup regressions retain HTML input/textarea/select/button declarations as
synthetic `html:input` (etc.) calls with keyword fields, distinct from CFScript
member calls such as `html.input()`. CFINPUT/CFSELECT/CFTEXTAREA retain their tag
names. These are source declarations, not DOM reachability or submission facts.
HTML comments, raw-text bodies, ordinary attributes, CFML strings/comments and
CFScript are separated without hiding server-side CFML operations. CFOUTPUT
interpolation is recognized in source order; generated markup remains expression
text. Outside CFOUTPUT, ordinary HTML hashes stay literal.

Conditional attribute suffixes expose only an unconditional prefix and report
partial markup syntax. The retained datasource shell supplies cmd/opts/timeout
examples. Arbitrary server code inside a start tag remains unavailable. Numeric
character references and five basic named references are decoded; unsupported
named references become unknown. Constant decoding shares the existing byte
budget. Tests cover contexts, offsets, every prefix, tag/attribute/depth limits,
invalid numeric scalars/C1 mappings and non-colliding call targets.

HTML semantics reference: https://html.spec.whatwg.org/multipage/parsing.html
This bounded source tokenizer does not implement a complete browser DOM, error
recovery, scripting, foreign-content integration, or runtime-rendered markup.

The decoded shell also covers all three CFFILE read-result bindings in the
producer tests. Static result names replace prior values; conditional results
retain alternatives and dynamic names/actions invalidate stale aliases.

Response tests use the decoded shell to verify both direct FileContent output
expressions and the original CFHEADER/CFCONTENT offsets. Synthetic controls
cover query ambiguity, reassignment, function-name impersonation and truncation.

The retained datasource shell now tests the exact decryptPassword assignment
offset and its Decrypt-to-writeOutput value path within the IF block. Synthetic
controls ensure branch/function boundaries and object fields do not leak aliases.
