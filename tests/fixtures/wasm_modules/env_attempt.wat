;; Adversarial fixture: imports wasi_snapshot_preview1.environ_get. The
;; WasmToolRunner does NOT link any WASI imports, so this module must fail
;; to instantiate. If it ever succeeds, the runner is leaking the host
;; environment.
(module
  (import "wasi_snapshot_preview1" "environ_get"
    (func $environ_get (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "try_env")
    (drop (call $environ_get (i32.const 0) (i32.const 0)))))
