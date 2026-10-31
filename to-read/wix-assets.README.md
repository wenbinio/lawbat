# App icon

`Product.wxs` references `assets\app.ico` for the ARP entry and both shortcuts.

**`app.ico` IS committed, but it's a minimal 16x16-only placeholder** — enough for `wix build`
to succeed, not real branding. A proper multi-resolution Windows `.ico` (16/32/48/256 px)
should replace it before a polished/public ship; it can't be authored on the Linux dev box, so
do it on Windows, e.g. `magick convert logo-256.png -define icon:auto-resize=256,48,32,16
app.ico`. To build a test MSI with a different icon, point `<Icon SourceFile=...>` at any
temporary `.ico`.

**`redactor.ico` is a generated placeholder too** (like `app.ico`) — a 7-size
(16-256 px) redaction-bars-on-document motif referenced by the standalone Redactor variant
(`build/wix/Redactor.wxs`) for its ARP entry + shortcuts. Distinct from `app.ico` so the two
products read differently in Start-menu / Add-Remove-Programs; replace with real branding
before a polished/public ship.
