# elf-syscall-wrapper-*.elf

Inert x86-64 Linux executables that call `memfd_create` (319) through the libc
`syscall()` wrapper with constant arguments. Never execute fixtures. Written
for this project (Apache-2.0); the `static` build also contains musl (MIT).

| File | SHA-256 |
|---|---|
| `elf-syscall-wrapper-static.elf` | `d6d441565aa0b3f04129637c25e9e48f1efeee18f26c977d46de97bc8f4625de` |
| `elf-syscall-wrapper-plt.elf` | `bce10d32904980b17300048adbd3f477f22628eaa9a63d3fb1876504931f46f7` |
| `elf-syscall-wrapper-noplt.elf` | `97e01a86dae540ed34fd5059bfaf59de9c12bbde34f92fa479e231166708a18f` |
| `elf-syscall-wrapper-ibt.elf` | `4dcd9e665c7528510b276bc910b09e8a5bc18b5faf42cd09a50b4b280e749653` |

Source:

```c
/* Inert fixture: issues memfd_create through the libc syscall() wrapper. */
#include <unistd.h>

int exported_entry(void) { return 7; }

int main(int argc, char **argv) {
	(void)argv;
	if (argc != 42)
		return exported_entry();
	return (int)syscall(319, "fixture", 1, 2, 3, 4);
}
```

Built with zig 0.17.0, then debug info dropped with llvm-objcopy so `.symtab`
survives:

```
zig cc -target x86_64-linux-musl -static -O2 -g -fno-asynchronous-unwind-tables -o static.full wrapper.c
zig cc -target x86_64-linux-gnu.2.17 -O2 -g -rdynamic -fno-asynchronous-unwind-tables -o plt.full wrapper.c
zig cc -target x86_64-linux-gnu.2.17 -O2 -g -fno-plt -fno-asynchronous-unwind-tables -o noplt.full wrapper.c
llvm-objcopy --strip-debug --remove-section=.comment <name>.full elf-syscall-wrapper-<name>.elf
```

- `static`: musl defines `syscall` and its other entry points as `.symtab`
  globals, with no `.dynsym`. The call at file offset `0x600` targets it.
- `plt`: imports `syscall`; the call at `0x712` targets its lazy PLT stub, which
  lld places after `.text`. `-rdynamic` exports `exported_entry` and `main`.
- `noplt`: imports `syscall`; the call at `0x542` is `call [rip+GOT slot]`.
- `ibt`: `plt` with the `syscall` stub (file offset `0x7b0`) rewritten in the
  IBT `.plt.sec` shape that zig's driver cannot request from lld:
  `endbr64; jmp [rip+0x1176]` then six `int3`, reaching the same GOT slot
  (`0x1002930`). The lazy-binding `push`/`jmp` are gone, which is harmless for
  a fixture that never runs.
