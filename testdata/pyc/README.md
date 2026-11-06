# Python bytecode fixtures

Small `.pyc` files for the marshal code-object walker in
`src/formats/pyc.rs` (tests in `src/formats/pyc/tests.rs`). They are not
specimens: each was compiled by CPython from a short fixture module, whose
name is recorded in the code object, and the header's flags, source mtime
and source size fields are zeroed. The fixture modules themselves are not
checked in; their exact source is to be documented.

| File | SHA-256 | Python | Module | What the tests assert |
|---|---|---|---|---|
| `names-311.pyc` | `3c8ac3e601bf670f94803a4e310d116ae1b177b4ef84ae241b08b0cce3f61cf8` | 3.11 | `identifier-fixture.py` | Names (`strip`, `replace`, `startswith`, `lstrip`) become identifiers whose offsets point into the original bytes |
| `names-314.pyc` | `6b4a25b9f42147468c93f03ff099ae335cef9ac61b77d7704827cef3e60a56ed` | 3.14 | `identifier-fixture.py` | Names become identifiers; `pyc.python_version` is `3.14`; every truncation yields a diagnostic and no partial identifiers |
| `strings-314.pyc` | `fe96a6deceb8f9018c5f9392e308a4134bf3e9b49aeb3df5b6c53841d276e4b6` | 3.14 | `catalog-fixture.py` | A module of string constants yields its one name, `CATALOG`, and no identifiers from the constants |
