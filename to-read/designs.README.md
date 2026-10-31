# designs/

Claude Design mockups (`*.dc.html`) that drive the dashboard, committed here so they're versioned
next to the code they shape and don't need re-uploading each session (the private
`claude.ai/design/...` URLs aren't reachable from a remote session).

## Workflow
1. In Claude Design, export the file (e.g. `Department Cockpits - Directions.dc.html`).
2. Drop it here and commit.
3. Implementing it = porting the layout into `app/web.py` as a real view — self-contained (no
   CDN/web-fonts, air-gapped), wiring panels onto existing endpoints (corpus stats, document
   manifest, automations, search) to live data, and stubbing/flagging anything needing data we
   don't yet collect.

## Status
| File | Imported | Implemented | Notes |
|------|----------|-------------|-------|
| `redaction.dc.html` | ✅ | ✅ | reference mockup that locked the redaction design system (tokens, unified topbar, component library) — see `to-read/pilot.md` "UI/UX — the remaining gap". |
| `redaction-reviewer.dc.html` | ✅ | ✅ | full staged-preview-driven reviewer mockup; drove the live `/redaction` implementation. |
| `dashboard-prototype.dc.html` | ✅ | 🟡 partial | Home dashboard prototype; not yet the sole source for `app/ui/home.*` — treat as directional. |
