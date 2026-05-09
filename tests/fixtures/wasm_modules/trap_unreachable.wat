;; Adversarial fixture: deliberately traps via the `unreachable` opcode. The
;; runner must surface this as a WasmToolError, not crash the host.
(module
  (func (export "boom") (result i32)
    (unreachable)))
