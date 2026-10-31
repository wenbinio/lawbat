"""
Deterministic file classification shared across indexing, corpus stats, and the
document manifest — so "is this a scanned PDF / an image / searchable?" is
answered in exactly one place instead of being re-derived per module.
"""

# Raster image formats: present in a data room but have NO text layer until OCR.
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".gif",
              ".heic", ".heif", ".webp"}


def is_scanned_pdf(ext: str, extract_status: str) -> bool:
    """A PDF that yielded no extractable text is almost certainly a scan."""
    return (ext or "").lower() == ".pdf" and extract_status == "empty"


# Files the INGESTION SAFETY ENVELOPE skipped BEFORE opening them (scan_guard policy):
# a cloud placeholder (opening forces a download), an over-cap blob, or a denied tree.
# Kept here so "what does this status mean?" is answered in exactly one place, like the
# extractor statuses above.
_SKIP_LABELS = {
    "skipped-offline": "online-only — skipped to avoid a cloud download",
    "skipped-too-large": "too large — skipped",
    "skipped-denied": "no permission — skipped",
}


def content_status(ext: str, extract_status: str) -> str:
    """Human-readable 'can I search this?' label, derived from extract status."""
    ext = (ext or "").lower()
    if extract_status == "ok":
        return "searchable"
    if extract_status == "truncated":
        # The extractor hit its expanded-text byte/element cap: the text we DID get
        # (up to the cap) is real and indexed/searchable — only the tail was dropped.
        return "searchable (truncated — very large file)"
    if extract_status in _SKIP_LABELS:
        return _SKIP_LABELS[extract_status]
    if extract_status == "empty":
        if ext == ".pdf":
            return "scanned — no text (OCR needed)"
        return "no text found"
    if extract_status == "unsupported":
        if ext in IMAGE_EXTS:
            return "image — no text (OCR needed)"
        return "unsupported type"
    if extract_status == "error":
        return "error"
    return extract_status or "unknown"
