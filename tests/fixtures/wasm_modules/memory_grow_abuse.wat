;; Adversarial fixture: tries to grow memory by an enormous amount. With
;; the runner's memory cap, the grow call should return -1 (failure) and
;; never hand the module the requested pages. The runner enforces the cap
;; via wasmtime's StoreLimits.
(module
  (memory (export "memory") 1)
  (func (export "grow_lots") (result i32)
    ;; Try to grow by 4096 pages = 256 MiB. Should fail under the runner's
    ;; small memory cap (default ≤ 16 pages).
    (memory.grow (i32.const 4096))))
