;; Calculator module for SIFR's WasmToolRunner.
;;
;; Pure computation: no imports, no memory, no host calls. Compiled and
;; instantiated by sifr/wasm_runner.py with no WASI bindings, so the module
;; cannot reach the host filesystem, network, or environment even if it tried.
;;
;; This is .wat (WebAssembly text) on purpose — it is human-reviewable and
;; wasmtime compiles it at load time. There is no opaque .wasm binary in git.
(module
  (func (export "add") (param i64 i64) (result i64)
    (i64.add (local.get 0) (local.get 1))))
