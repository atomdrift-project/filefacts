# Compiled AppleScript

Filefacts reads `FasdUAS` scripts without running AppleScript or sending
AppleEvents. Plaintext `.applescript` files keep their existing extraction.

## Facts

| View | Evidence |
| --- | --- |
| `literals` | UTF-16BE text and recovered constant strings, with file offsets |
| `symbols`, `kind: import` | Referenced AppleEvents, named `class.event` |
| `symbols`, `kind: function` | Handlers and their callees |
| `symbols`, `kind: call` | Decoded call instructions and known arguments |
| `values.scpt.version` | UAS version |
| `values.scpt.limits` | Reason for incomplete analysis; handler when applicable |
| `metrics.scpt.handlers` | Handlers found |
| `metrics.scpt.calls` | Call instructions found |
| `metrics.scpt.decoded` | Recovered strings |

An import proves that an event is referenced. A call proves that a decoded
instruction names it. Neither proves runtime execution. Missing arguments
remain unknown; they never contain guessed values.

Call arguments are positional. For AppleEvents, index 0 is the direct argument,
followed by keyword argument values in bytecode order. Keyword names are not
yet exposed.

Literal methods distinguish `scpt-literal` (stored text) from `scpt-constant`
(reconstructed text). A reconstructed string's offset points to the instruction
that produced or consumed it. Its bytes need not be contiguous in the file.

Stored and reconstructed literals also receive one pass through stng's shared
string decoders. Results are additional literals, labeled `scpt-base64`,
`scpt-hex`, and so on. They keep the parent literal's source anchor. Original
literals and call arguments are unchanged; decoding alone does not prove that
the script uses the decoded value.

## Traits

Match a shell call and its argument together:

```yaml
if:
  type: symbol
  kind: call
  exact: syso.exec
  arg:
    index: 0
    kind: string
    substr: "security find-generic-password"
```

Use `type: literal` for stored or recovered text. Combine sensitive targets,
collection, and transport in objective traits. A shell call or a cookie path
alone does not establish theft.

## Bounds

The reader bounds input, objects, references, nesting, and owned data. The
instruction walker bounds work and stops at unknown instruction widths.
Constant propagation clears state at control-flow joins and operations whose
effects are not modeled.

Stored text is decoded once per payload, with an 8 MiB input budget. Invalid
UTF-16 consumes that budget too. Legacy FAS-12 text/style records are skipped
because their text encoding is not established. Native Unicode vectors remain
supported.

Shared decoding accepts up to 4,096 literals and 8 MiB of input, with a
256 KiB limit per literal. Output is capped at 4,096 strings and 8 MiB.
Limits appear in `scpt.limits`; decoded results count toward `scpt.decoded`.

Extraction currently requires `Fasd` at byte zero. Shebang-prefixed compiled
scripts are not extracted, although the structural reader accepts the prefix.

String recovery currently recognizes five complete arithmetic decoder bodies,
including their literal types, loop edges, and parameter counts. Recognition
does not depend on handler names or encoded text. Changes to those bodies may
prevent recovery. This is a limited disassembler, not a general decompiler.

No shell command, network request, application operation, or script is executed
during extraction.
