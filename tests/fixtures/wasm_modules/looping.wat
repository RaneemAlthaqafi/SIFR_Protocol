;; Adversarial fixture: an infinite loop. Used to verify that
;; sifr/wasm_runner.py's fuel limit traps the module before it consumes
;; unbounded host CPU.
(module
  (func (export "spin")
    (loop $l (br $l))))
