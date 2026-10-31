"""
Cheap export formats for the redaction reviewer's TEXT path.

The PDF path already writes a redacted PDF to the exports dir and reveals it. The TEXT
path (pasted text, or an extracted .eml/.docx/.txt/...) historically offered only Copy.
This module adds stdlib-only formatters that turn the ALREADY-REDACTED text (the output
of redact-cli's `apply`) into a handful of approachable file formats the host writes to
the exports dir (never the read-only source tree, never-overwrite).

TWO KINDS OF OUTPUT — keep them apart:

  1. The REDACTED / LABELED document (.txt / .md / .html / .json). This contains ONLY
     redacted-or-labeled content — the `[REDACTED]` marker, or `[A]`/`[email 1]`/typed
     placeholders. It NEVER contains an original cleartext value. The labeled .md is the
     AI-FRIENDLY artifact — labels let an AI tool track who-is-who — but it is STILL a
     first pass, never "safe to send"; the user reviews it before relying on it.

  2. The RE-IDENTIFICATION KEY (labels mode only). This maps each label -> its ORIGINAL
     value, so it CONTAINS CLEARTEXT PII. It is written as a SEPARATE file, carries a loud
     keep-local header, and is NEVER embedded in the redacted/labeled output. The labeled
     document and the key are a pair the user keeps locally; only the labeled document is
     AI-friendly (the key never leaves the machine).

SECURITY PROPERTY (tested): the redacted/labeled outputs carry no original value; the key
is a separate artifact carrying the keep-local banner. The two never mix. (The no-cleartext
property assumes the engine emits OPAQUE labels like `[A]`/`[email 1]`, which redact-cli
guarantees — a label is never itself an original value.)

LOCAL-ONLY / AIR-GAP: the .html output is fully self-contained and HTML-escaped — no
external <link>/<script>/<img>, no web fonts, no external resource references (so the same
air-gap discipline holds for the written file). A literal URL that appears inside the
redacted text is inert HTML-escaped <pre> content, not a loaded resource. Pure stdlib
(json + html), deterministic, no network, no logging of cleartext here.
"""

from __future__ import annotations

import html as _html
import json as _json
import re as _re

# The formats a TEXT redaction may be saved as. Each maps to a file suffix; the UI labels
# them in plain language (Plain text / Markdown / Web page / Data (JSON) / AI-safe labels).
# An unknown format coerces to the safe ".txt" default (never an error).
TEXT_EXPORT_FORMATS = ("txt", "md", "html", "json")
_SUFFIX = {"txt": ".txt", "md": ".md", "html": ".html", "json": ".json"}

# The loud, in-file banner the re-identification KEY carries. It is the FIRST thing in the
# key file (every format) so a user who opens it cannot miss that it holds real names and
# must stay local. Plain ASCII / no markup so it reads the same in every editor.
KEY_BANNER_LINES = (
    "RE-IDENTIFICATION KEY — contains the ORIGINAL names/values this redaction "
    "replaced.",
    "Keep this on your machine. Do NOT send it with the redacted document, and never "
    "paste it into an AI tool.",
    "It is the only thing that turns the labels back into real people — delete it "
    "when you are done.",
)


def normalize_format(fmt) -> str:
    """Coerce a requested export format to an allowlisted value. Anything outside
    TEXT_EXPORT_FORMATS -> 'txt' (the safe default). Never raises."""
    if isinstance(fmt, str) and fmt.lower() in TEXT_EXPORT_FORMATS:
        return fmt.lower()
    return "txt"


def suffix_for(fmt: str) -> str:
    """The filename suffix for an (already-normalized) format."""
    return _SUFFIX.get(fmt, ".txt")


def _legend_rows(legend) -> list[dict]:
    """Validate + normalize a legend (the label->value map). Each kept row is
    `{label, value, count}` with string label/value and an int count >= 1. A malformed
    entry is dropped (never raises). Used by both the key file and the JSON counts."""
    out: list[dict] = []
    if not isinstance(legend, (list, tuple)):
        return out
    for e in legend:
        if not isinstance(e, dict):
            continue
        label = e.get("label")
        value = e.get("value")
        if not isinstance(label, str) or not isinstance(value, str):
            continue
        count = e.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            count = 1
        out.append({"label": label, "value": value, "count": count})
    return out


# ---------------------------------------------------------------------------------------
# The REDACTED / LABELED document formatters. Each takes the redacted text (already free of
# original values) + metadata and returns bytes ready to write. NONE of these ever receives
# or emits an original cleartext value — they format `redacted_text` only.
# ---------------------------------------------------------------------------------------

def format_txt(redacted_text: str) -> str:
    """Plain text: the redacted text verbatim."""
    return redacted_text if isinstance(redacted_text, str) else ""


def format_md(redacted_text: str, *, labeled: bool) -> str:
    """Markdown: the redacted text in a fenced block under a short heading. For the labeled
    (AI-safe) style the heading names it so a user pasting it into an AI tool sees it is the
    safe artifact. The text is placed in a fenced code block so its own characters can't be
    misread as Markdown; a literal ``` inside the text is defended by widening the fence."""
    text = redacted_text if isinstance(redacted_text, str) else ""
    title = "Redacted document (AI-friendly labels)" if labeled else "Redacted document"
    note = (
        "Each removed item is a label (e.g. `[A]`, `[email 1]`) so an AI tool can keep "
        "track of who is who. This is STILL a first pass, not "
        '"safe to send" — read it before you rely on it; labels do not guarantee every '
        "identifier was caught. The key that maps labels back to real names is a SEPARATE "
        "file kept on your machine — never send it."
        if labeled
        else "Each removed item is marked `[REDACTED]`. This is a first pass, not "
        '"safe to send" — read it before you rely on it.'
    )
    # Pick a fence longer than the longest run of backticks in the body so the body can
    # never break out of the code block.
    longest = 0
    run = 0
    for ch in text:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    fence = "`" * max(3, longest + 1)
    return f"# {title}\n\n{note}\n\n{fence}\n{text}\n{fence}\n"


def format_html(redacted_text: str, *, labeled: bool) -> str:
    """Self-contained, HTML-escaped web page of the redacted text. NO external resources
    (no <link>/<script>/<img>, no web fonts, no external resource references) so the air-gap
    discipline holds for the written file just as it does for the served page. (A URL that
    appears inside the redacted text is inert HTML-escaped <pre> content, not a loaded
    resource.) The text is escaped via html.escape before it ever reaches markup."""
    text = redacted_text if isinstance(redacted_text, str) else ""
    title = "Redacted document (AI-friendly labels)" if labeled else "Redacted document"
    note = (
        "Each removed item is a readable label so an AI tool can keep track of who is who. "
        "Still a first pass — read it before you rely on it; labels do not guarantee every "
        "identifier was caught. The key that maps labels back to real names is a separate "
        "file kept on your machine."
        if labeled
        else "Each removed item is marked [REDACTED]. A first pass — read it before "
        "you rely on it."
    )
    esc_text = _html.escape(text)
    esc_title = _html.escape(title)
    esc_note = _html.escape(note)
    # A minimal inline-styled, self-contained document. No DOCTYPE URL, no namespace URI,
    # no external anything — the page loads zero remote resources. (A URL inside the
    # redacted text lands inert in the escaped <pre>; it is content, not a resource.)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{esc_title}</title>\n"
        "<style>\n"
        "  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;\n"
        "         margin: 2rem auto; max-width: 48rem; line-height: 1.5; color: #1a1a1a; }\n"
        "  h1 { font-size: 1.3rem; }\n"
        "  .note { color: #555; font-size: 0.9rem; margin-bottom: 1.25rem; }\n"
        "  pre { white-space: pre-wrap; word-wrap: break-word; background: #f6f6f6;\n"
        "        border: 1px solid #ddd; border-radius: 6px; padding: 1rem; }\n"
        "</style>\n</head>\n<body>\n"
        f"<h1>{esc_title}</h1>\n"
        f'<p class="note">{esc_note}</p>\n'
        f"<pre>{esc_text}</pre>\n"
        "</body>\n</html>\n"
    )


def format_json(redacted_text: str, *, fmt_label: str, counts: dict) -> str:
    """Structured JSON of the redacted document. Carries `redacted_text` (no original
    values), the `format` label, and `counts` (applied / stale / per-label occurrence
    counts) — NEVER an original cleartext value. The label->value mapping lives ONLY in the
    separate key file."""
    text = redacted_text if isinstance(redacted_text, str) else ""
    doc = {
        "schema": "lawbat.redacted-text/0",
        "format": str(fmt_label),
        "redacted_text": text,
        "counts": counts if isinstance(counts, dict) else {},
        # An explicit, machine-readable affirmation of the security property: this file
        # holds no original values; re-identification needs the separate key file.
        "contains_original_values": False,
    }
    return _json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def build_redacted_document(
    redacted_text: str,
    fmt: str,
    *,
    labeled: bool,
    applied: int = 0,
    stale: int = 0,
    legend=None,
) -> str:
    """Render the redacted/labeled document in `fmt` (already normalized). The output NEVER
    contains an original cleartext value — for JSON the legend is reduced to counts only
    (label + occurrence count, no value)."""
    if fmt == "md":
        return format_md(redacted_text, labeled=labeled)
    if fmt == "html":
        return format_html(redacted_text, labeled=labeled)
    if fmt == "json":
        counts: dict = {"applied": int(applied), "stale": int(stale)}
        if labeled:
            # Per-label OCCURRENCE counts only — the label token + how many times it stood
            # in. NO value. (`[A] -> 3` tells you nothing about who [A] is.)
            counts["labels"] = [
                {"label": r["label"], "count": r["count"]} for r in _legend_rows(legend)
            ]
        return format_json(redacted_text, fmt_label="labels" if labeled else "redacted",
                           counts=counts)
    # txt (and the safe default)
    return format_txt(redacted_text)


# ---------------------------------------------------------------------------------------
# The RE-IDENTIFICATION KEY. Labels mode only. CONTAINS CLEARTEXT — a SEPARATE file, loud
# banner, never embedded in the redacted/labeled output.
# ---------------------------------------------------------------------------------------

def build_key_txt(legend) -> str:
    """The plain-text re-identification key: the keep-local banner, then `label = value`
    rows. CONTAINS CLEARTEXT ORIGINAL VALUES — written to its own file, never to the
    redacted output."""
    rows = _legend_rows(legend)
    lines = list(KEY_BANNER_LINES)
    lines.append("")
    lines.append("=" * 60)
    lines.append("")
    for r in rows:
        suffix = f"   (appears {r['count']}x)" if r["count"] > 1 else ""
        lines.append(f"{r['label']} = {r['value']}{suffix}")
    return "\n".join(lines) + "\n"


def build_key_json(legend) -> str:
    """The JSON re-identification key: a top-level `WARNING` banner string + the label->value
    map. CONTAINS CLEARTEXT ORIGINAL VALUES — its own file, never embedded in the output."""
    rows = _legend_rows(legend)
    doc = {
        "schema": "lawbat.reidentification-key/0",
        "WARNING": " ".join(KEY_BANNER_LINES),
        "contains_original_values": True,
        "key": [
            {"label": r["label"], "value": r["value"], "count": r["count"]} for r in rows
        ],
    }
    return _json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------------------
# The LABELED MARKDOWN working copy (AI-prep). A SECOND, clearly-SEPARATE artifact from the
# production redacted PDF: it rebuilds a document's text as a Markdown .md with identifiers
# replaced by LABELS, for AI-assisted drafting. It NEVER contains an original value (it
# formats the ALREADY-LABELED apply output only — the label -> value key is the separate
# key file above). The AI-prep vs production-privilege boundary is stated IN the header,
# verbatim, so a reader who opens the .md cannot mistake it for the production document.
# ---------------------------------------------------------------------------------------

# The plain-language boundary statement the labeled-Markdown header carries VERBATIM. Tests
# pin this string byte-for-byte (it IS the AI-prep vs production boundary the feature exists
# to make impossible to miss) — do NOT reword it without updating them. Em dash is U+2014.
LABELED_MD_STATEMENT = (
    "Rebuilt from text extraction — layout, tables and images are not preserved. "
    "Labels replace redacted identifiers; the label key is a separate file. "
    "Working copy for AI-assisted drafting — NOT the production redacted document."
)


def _md_body_from_text(text: str) -> str:
    """Render an ALREADY-LABELED plain-text block as a light-structure Markdown body:
    paragraphs (blank-line-delimited blocks in the source text) are preserved and separated
    by a blank line; each paragraph's own internal single newlines are kept as-is. NO
    headings, tables, or other structure is invented — a text extractor hands us a flow of
    text, and we present it honestly as a flow of text. A lone ``\\r`` / ``\\r\\n`` is
    normalised to ``\\n`` first. NEVER contains an original value (it formats labeled text)."""
    if not isinstance(text, str):
        return ""
    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    # Split on a blank line (a run of a newline, optional spaces/tabs, another newline) into
    # paragraphs; drop empties; re-join with a blank line so structure is neither invented
    # nor destroyed.
    paras = [p.strip("\n") for p in _re.split(r"\n[ \t]*\n", norm)]
    paras = [p for p in paras if p.strip()]
    return "\n\n".join(paras)


def build_labeled_markdown(
    labeled_text: str,
    *,
    source_filename: str,
    source_sha256: str,
    generated_utc: str,
    app_version: str,
    pages=None,
) -> str:
    """Assemble the AI working-copy Markdown from ALREADY-LABELED text (the ``apply`` output
    with the ``labels`` style — labels like ``[A]`` / ``[email 1]``, NEVER original values).

    Structure:
      * an HONEST header block — the source filename + SHA-256, generated-by + version, the
        UTC date, and the plain :data:`LABELED_MD_STATEMENT` boundary (AI working copy, NOT
        the production redacted document);
      * a ``---`` thematic break;
      * the body — the labeled text as light-structure Markdown (see ``_md_body_from_text``).

    ``pages`` (optional): a list of per-page ALREADY-LABELED strings. It is used ONLY when the
    extractor genuinely provides page boundaries. When given, pages 2..N are separated by a
    ``---`` rule + a ``*Page N*`` marker. When None/empty (today's ``extract_scan`` path, which
    joins pages with a bare newline and surfaces NO page boundaries) the body is a single
    honest flow — NO fake page markers are invented. ``generated_utc`` + ``app_version`` are
    passed IN so this stays deterministic + unit-testable.

    NEVER contains an original cleartext value — it formats ``labeled_text`` / ``pages`` only;
    the label -> value mapping lives ONLY in the separate key file (``build_key_txt``)."""
    name = str(source_filename or "document")
    header = (
        f"# Labeled working copy — {name}\n\n"
        f"- **Source file:** {name}\n"
        f"- **Source SHA-256:** {source_sha256}\n"
        f"- **Generated by:** Lawbat {app_version}\n"
        f"- **Generated (UTC):** {generated_utc}\n\n"
        f"{LABELED_MD_STATEMENT}\n\n"
        "---\n"
    )
    if isinstance(pages, (list, tuple)) and pages:
        blocks: list[str] = []
        for i, page_text in enumerate(pages, 1):
            body = _md_body_from_text(page_text if isinstance(page_text, str) else "")
            if i == 1:
                blocks.append(body)
            else:
                # A REAL page boundary from the extractor -> an honest rule + page marker.
                blocks.append(f"---\n\n*Page {i}*\n\n{body}")
        body_md = "\n\n".join(blocks)
    else:
        body_md = _md_body_from_text(labeled_text)
    return header + "\n" + body_md + "\n"
