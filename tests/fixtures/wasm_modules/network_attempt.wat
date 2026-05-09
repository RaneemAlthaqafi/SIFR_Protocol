;; Adversarial fixture: imports wasi_snapshot_preview1.sock_send. WASI's
;; preview1 socket extension is the closest standard "network" surface, and
;; the SIFR runner must refuse to link it. Instantiation must fail.
(module
  (import "wasi_snapshot_preview1" "sock_send"
    (func $sock_send (param i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "try_send")
    (drop (call $sock_send
      (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))))
