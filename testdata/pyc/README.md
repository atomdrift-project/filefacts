# Python bytecode fixtures

Small `.pyc` files for the marshal code-object walker in
`src/formats/pyc.rs` (tests in `src/formats/pyc/tests.rs`). They are not
specimens: each was compiled by CPython from a short fixture module, whose
name is recorded in the code object, and the header's flags, source mtime
and source size fields are zeroed. The fixture modules themselves are not
checked in; their exact source is to be documented.

| File | SHA-256 | Python | Module | What the tests assert |
|---|---|---|---|---|
| `names-311.pyc` | `3c8ac3e601bf670f94803a4e310d116ae1b177b4ef84ae241b08b0cce3f61cf8` | 3.11 | `identifier-fixture.py` | Names (`strip`, `replace`, `startswith`, `lstrip`) become identifiers whose offsets point into the original bytes; its constant `Bearer ` becomes a literal |
| `names-314.pyc` | `6b4a25b9f42147468c93f03ff099ae335cef9ac61b77d7704827cef3e60a56ed` | 3.14 | `identifier-fixture.py` | Names become identifiers; `pyc.python_version` is `3.14`; every truncation yields a diagnostic and no partial identifiers |
| `strings-314.pyc` | `fe96a6deceb8f9018c5f9392e308a4134bf3e9b49aeb3df5b6c53841d276e4b6` | 3.14 | `catalog-fixture.py` | A module of string constants yields its one name, `CATALOG`, and no identifiers from the constants; its string constants become literals at their offsets, and no truncation yields a partial literal |
| `literals-38.pyc` | `0aaf506d86581a50c4e5ad40fa6014ce3a18d691dcffeab43da6f8b5bd06e583` | 3.8.20 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |
| `literals-39.pyc` | `fad598b9386854019bc9a52d3d4ba4bb270721ae9521997e639277de09cfaf2d` | 3.9.6 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |
| `literals-310.pyc` | `af58a00120d7547b4e8d508e537ff5ebdce6cabc0ae280776aded25da1932873` | 3.10.20 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |
| `literals-311.pyc` | `9d6eeadaebbaaa06f6b0ef192edda2c4366d507adae973e6ba0314099ec69091` | 3.11.15 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |
| `literals-312.pyc` | `e50c0d7c110f36e5810b889eb794cbf1867a73d6725782e21c34efd46fdf42d8` | 3.12.16 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |
| `literals-313.pyc` | `1bcae5f18159ad3417ad866ac7eef115c1a0f257e328bec4437c22351e1c6f25` | 3.13.14 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |
| `literals-314.pyc` | `dc023424372fce3e915eaae831f9c31c2ef00bedd95534834d73b857ca777c9a` | 3.14.10 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |
| `literals-315.pyc` | `21e168a2eca68a41ac5bd5be3ed4040981f543b21ac98272b656a0dbb4b52997` | 3.15.2 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |
| `literals-316.pyc` | `9658929eafa0d7a49a53595454e213d6beb3ca502840eef8637d82cd23e72282` | 3.16.0a2 | `literal_fixture.py` | Every string literal of the module below, at its offset; `pyc.python_version` names the release |

The `literals-*.pyc` files were compiled with `py_compile` in unchecked-hash
mode (PEP 552), so they carry no mtime. Their module, `literal_fixture.py`:

```python
"""Module docstring for the literal fixture."""
TOKEN = "1234567890:AAEhBP0av18o8wSxQkJt-2A_bCdEfGhIjKl"
BLOB = b"bytes-constant-value"
MODES = ("first-mode", "second-mode")


def handler(event):
    """Handle one event."""
    if event in ("open", "close"):
        return "nested-function-literal"
    return lambda: "lambda-literal"


class Widget:
    label = "class-body-literal"
```

Python 2.7 and 3.0 through 3.7 are covered by code objects the tests
assemble byte by byte to each release's documented layout, as no current
interpreter writes them.
