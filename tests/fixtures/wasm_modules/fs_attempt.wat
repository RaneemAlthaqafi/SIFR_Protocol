;; Adversarial fixture: imports wasi_snapshot_preview1.path_open. The
;; WasmToolRunner does NOT link any WASI imports, so this module must fail
;; to instantiate. If it ever succeeds, the runner is leaking host
;; capabilities and the trap-acceptance test fails.
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "try_open")
    (drop (call $path_open
      (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
      (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 0)))))
