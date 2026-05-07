# Paper Evidence Log

Append one paragraph per implemented v0.2 feature, with file paths, test names, and metric values. The Phase-5 paper revision pass consumes this log directly. **Do not summarize from memory** — every claim in `paper/main.tex` must trace back to an entry here.

Template per entry:

```
## <feature> — <YYYY-MM-DD>

**Code:** `<path>` (key functions: `<f1>`, `<f2>`)
**Tests:** `tests/<test_file>::<test_name>` (positive); `tests/<test_file>::<negative_test>` (reject path)
**Demo:** `examples/<demo>.py`
**Benchmark:** `benchmarks/<bench>.py` → `benchmarks/results/<output>` (key metric: <value> ± <stdev>)
**Documentation:** `docs/<doc>.md`
**Claim made in paper:** "<exact claim text>"
**Claim NOT made:** <what we explicitly do not claim and why>
**Trap-acceptance test:** `tests/<file>::<adversarial_test>` — proves implementation is real, not in-name-only
```

---

## Pre-phase refactor — 2026-05-08

**Code:** `sifr/canonical.py` (canonicalization), `sifr/keyring_iface.py` (KeyResolver Protocol), `sifr/crypto.py:verify_message` (resolver overload), `sifr/transport/` (package split)
**Tests:** all 27 v0.1 tests still pass after refactor (`pytest -q`)
**Claim:** none (refactor only). Pre-phase establishes the seams later phases plug into.
