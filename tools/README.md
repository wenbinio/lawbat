# genharness.py — fresh-corpus redaction generalization harness

Measures OFF-corpus redaction quality as a NUMBER: it plants SYNTHETIC identities
(fictional names + valid-format IDs) into hard document shapes, drives both product
routes (text-PDF byte-splice and scanned/OCR-burn), then RECOVERY-red-teams each output
(re-extract text + raw bytes / re-OCR) and counts **post-apply LEAKS** — planted values
that survived. FP pressure = candidates raised on an identity-free financial page.

Run:
```
PYTHONPATH=. LAWDATAMAN_REDACT_CLI=core/target/release/redact-cli \
    python3 tools/genharness.py --out /tmp/gh [--seed 7] [--scanned-subset 6]
```

Read the output: per class × path, `planted` (ground truth) / `detected` (flagged at
scan, diagnostic) / **`LEAKS`** (the headline — must trend to 0). Full detail +
per-leak values in `<out>/report.json`. Exit is always 0 (report-only). HONEST SCOPE:
a zero here proves removal of THESE shapes only — NOT a general safety claim.
