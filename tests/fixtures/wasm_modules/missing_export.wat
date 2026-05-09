;; Adversarial fixture: a valid module with no exported function called
;; `add`. When the runner is asked to call `add` on this module, it must
;; raise a clean error rather than crash, mis-dispatch, or silently return
;; a wrong value.
(module
  (func (export "subtract") (param i32 i32) (result i32)
    (i32.sub (local.get 0) (local.get 1))))
