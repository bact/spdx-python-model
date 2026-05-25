# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Lightweight SPDX utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SpdxVersionInfo:
    """Detected SPDX version and serialization format."""

    major: int
    minor: int | None = None
    patch: int | None = None
    file_format: str | None = None
    """Serialization format: ``"tag-value"``, ``"json"``, ``"yaml"``,
    ``"xml"``, ``"rdf-xml"``, ``"json-ld"``, or ``"turtle"``."""


# Each entry: (compiled pattern, file_format label).
# Version capture groups: (1) major, (2) minor (optional), (3) patch (optional).
# Patterns are tried in order; first match wins.
# More specific patterns (with patch-level version) are listed before coarser
# fallbacks (@context / @prefix URLs that only carry major.minor).
_VERSION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # SPDX 2.x tag:value:  SPDXVersion: SPDX-2.3
    (
        re.compile(
            r"^\s*SPDXVersion\s*:\s*SPDX-(\d+)(?:\.(\d+)(?:\.(\d+))?)?",
            re.MULTILINE,
        ),
        "tag-value",
    ),
    # SPDX 2.x JSON:  "spdxVersion": "SPDX-2.3"
    # Requires double-quoted key — distinguishes JSON from YAML.
    (
        re.compile(r'"spdxVersion"\s*:\s*"SPDX-(\d+)(?:\.(\d+)(?:\.(\d+))?)?'),
        "json",
    ),
    # SPDX 2.x YAML:  spdxVersion: SPDX-2.3  or  spdxVersion: 'SPDX-2.3'
    # Unquoted key at line start — distinguishes YAML from JSON's quoted key.
    (
        re.compile(
            r"^\s*spdxVersion\s*:\s*['\"]?SPDX-(\d+)(?:\.(\d+)(?:\.(\d+))?)?",
            re.MULTILINE,
        ),
        "yaml",
    ),
    # SPDX 2.x XML:  <spdxVersion>SPDX-2.3</spdxVersion>
    (
        re.compile(r"<spdxVersion>\s*SPDX-(\d+)(?:\.(\d+)(?:\.(\d+))?)?"),
        "xml",
    ),
    # SPDX 2.x RDF/XML:  <spdx:specVersion>SPDX-2.3</spdx:specVersion>
    (
        re.compile(r"[:<]specVersion>\s*SPDX-(\d+)(?:\.(\d+)(?:\.(\d+))?)?"),
        "rdf-xml",
    ),
    # SPDX 3.x JSON-LD specVersion field:  "specVersion": "3.0.1"
    # Double-quoted key + numeric value (no "SPDX-" prefix).
    (
        re.compile(r'"specVersion"\s*:\s*"(\d+)(?:\.(\d+)(?:\.(\d+))?)?'),
        "json-ld",
    ),
    # SPDX 3.x Turtle specVersion field:  spdx:specVersion "3.0.1"
    # Namespaced predicate + double-quoted numeric value.
    (
        re.compile(r"\w+:specVersion\s+\"(\d+)(?:\.(\d+)(?:\.(\d+))?)?"),
        "turtle",
    ),
    # SPDX 3.x JSON-LD @context URL (fallback — major.minor only):
    #   "@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld"
    (
        re.compile(
            r'"@context"\s*:\s*"https?://spdx\.org/rdf/(\d+)(?:\.(\d+)(?:\.(\d+))?)?'
        ),
        "json-ld",
    ),
    # SPDX 3.x Turtle @prefix — last resort, resolution depends on spec version:
    #   SPDX 3.0.x:  @prefix spdx: <https://spdx.org/rdf/3.0/> → major.minor (3, 0)
    #   SPDX 3.1+:   @prefix spdx: <https://spdx.org/rdf/3/>   → major only  (3, None)
    #   (Per spdx/spdx-3-model#1277, term IRIs no longer embed the minor version.)
    (
        re.compile(
            r"@prefix\s+\w+\s*:\s*<https?://spdx\.org/rdf/(\d+)(?:\.(\d+)(?:\.(\d+))?)?",
        ),
        "turtle",
    ),
]


def detect_spdx_version(file: str | Path) -> SpdxVersionInfo | None:
    """
    Detect the SPDX version and serialization format of a file.

    Inspects file content using regular expressions. Supports SPDX 2.x and
    3.x in tag:value, JSON, JSON-LD, YAML, XML, RDF/XML, and Turtle formats.
    Uses only the Python standard library; independent of the SPDX model bindings.

    Args:
        file: Path to the SPDX file.

    Returns:
        :class:`SpdxVersionInfo` with major, minor (if present), patch (if
        present), and file_format. Returns ``None`` if the file cannot be read
        or the version cannot be determined.
    """
    try:
        content = Path(file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return _detect_version_from_content(content)


def _detect_version_from_content(content: str) -> SpdxVersionInfo | None:
    for pat, fmt in _VERSION_PATTERNS:
        if m := pat.search(content):
            major = int(m.group(1))
            minor = int(m.group(2)) if m.group(2) is not None else None
            patch = int(m.group(3)) if m.group(3) is not None else None
            return SpdxVersionInfo(
                major=major, minor=minor, patch=patch, file_format=fmt
            )
    return None
