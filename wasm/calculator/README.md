# Calculator WASM module

A 13-line WebAssembly text (.wat) module exporting a single function:

```
add(a: i64, b: i64) -> i64
```

The implementation is one i64 add instruction. No imports, no memory, no host calls. It cannot reach the filesystem, network, or environment under any input — there is no host-import surface to abuse.

## Why .wat instead of .wasm in git

Committing a binary .wasm to a research repo is a code-review smell: reviewers cannot read it. We commit the .wat source instead and let `wasmtime` compile it at load time. Reviewers can verify by inspection that the module performs only an integer add.

## Usage

`sifr.wasm_runner.WasmToolRunner` loads this file by default. Tests may pass an alternate `modules_dir` to use fixture modules.

## Verification by hand

```bash
python -c "
import wasmtime
engine = wasmtime.Engine()
mod = wasmtime.Module(engine, open('wasm/calculator/calculator.wat').read())
store = wasmtime.Store(engine)
inst = wasmtime.Instance(store, mod, [])
print(inst.exports(store)['add'](store, 2, 3))
"
# -> 5
```

## Limitations

- This module is `add` only. Subtraction, multiplication, division etc. are out of scope for v0.2.
- The host configures fuel limits per-call via `WasmToolRunner(fuel=...)`. The module itself has no awareness of fuel.
- Negative integers are supported (i64 is signed two's-complement).
- Overflow wraps per WebAssembly's i64.add semantics.
