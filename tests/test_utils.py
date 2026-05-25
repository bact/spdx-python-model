# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

import pytest

from spdx_python_model.utils import (
    SpdxVersionInfo,
    _detect_version_from_content,
    detect_spdx_version,
)

V = SpdxVersionInfo  # shorthand for parametrize readability


# --- _detect_version_from_content ---


@pytest.mark.parametrize(
    "content, expected",
    [
        # SPDX 2.x tag:value
        ("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n", V(2, 3, None, "tag-value")),
        ("  SPDXVersion:SPDX-2.2\n", V(2, 2, None, "tag-value")),
        # SPDX 2.x JSON — double-quoted key
        ('"spdxVersion": "SPDX-2.3"', V(2, 3, None, "json")),
        ('"spdxVersion": "SPDX-2.2.1"', V(2, 2, 1, "json")),
        # SPDX 2.x YAML — unquoted key at line start
        ("spdxVersion: SPDX-2.3\n", V(2, 3, None, "yaml")),
        ("spdxVersion: 'SPDX-2.2'\n", V(2, 2, None, "yaml")),
        ('spdxVersion: "SPDX-2.3"\n', V(2, 3, None, "yaml")),
        # SPDX 2.x JSON must not be misidentified as YAML
        ('{\n  "spdxVersion": "SPDX-2.3"\n}', V(2, 3, None, "json")),
        # SPDX 2.x XML
        ("<spdxVersion>SPDX-2.3</spdxVersion>", V(2, 3, None, "xml")),
        ("<spdxVersion> SPDX-2.2 </spdxVersion>", V(2, 2, None, "xml")),
        # SPDX 2.x RDF/XML
        ("<spdx:specVersion>SPDX-2.2</spdx:specVersion>", V(2, 2, None, "rdf-xml")),
        ("<ns:specVersion>SPDX-2.3</ns:specVersion>", V(2, 3, None, "rdf-xml")),
        # SPDX 3.x JSON-LD via specVersion field (patch present)
        ('"specVersion": "3.0.1"', V(3, 0, 1, "json-ld")),
        # SPDX 3.x JSON-LD via specVersion field (no patch)
        ('"specVersion": "3.0"', V(3, 0, None, "json-ld")),
        # SPDX 3.x JSON-LD: specVersion preferred over @context when both present
        (
            '"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld",\n'
            '"specVersion": "3.0.1"',
            V(3, 0, 1, "json-ld"),
        ),
        # SPDX 3.x JSON-LD via @context URL (fallback, no patch)
        (
            '"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld"',
            V(3, 0, None, "json-ld"),
        ),
        # SPDX 3.x Turtle via specVersion field (patch present)
        ('spdx:specVersion "3.0.1" ;', V(3, 0, 1, "turtle")),
        # SPDX 3.x Turtle via @prefix (SPDX 3.0.x — major.minor)
        ("@prefix spdx: <https://spdx.org/rdf/3.0/> .", V(3, 0, None, "turtle")),
        # SPDX 3.x Turtle via @prefix (SPDX 3.1+ — major only; spdx/spdx-3-model#1277)
        (
            "@prefix spdx: <https://spdx.org/rdf/3/terms/Core/> .",
            V(3, None, None, "turtle"),
        ),
        # No match
        ("This is not an SPDX file.", None),
        ("", None),
    ],
)
def test_detect_version_from_content(content, expected):
    assert _detect_version_from_content(content) == expected


# --- detect_spdx_version ---


def test_detect_spdx_version_tag_value(tmp_path):
    f = tmp_path / "sbom.spdx"
    f.write_text("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n", encoding="utf-8")
    assert detect_spdx_version(f) == V(2, 3, None, "tag-value")


def test_detect_spdx_version_json(tmp_path):
    f = tmp_path / "sbom.spdx.json"
    f.write_text('{"spdxVersion": "SPDX-2.3"}', encoding="utf-8")
    assert detect_spdx_version(f) == V(2, 3, None, "json")


def test_detect_spdx_version_yaml(tmp_path):
    f = tmp_path / "sbom.spdx.yaml"
    f.write_text("spdxVersion: SPDX-2.3\n", encoding="utf-8")
    assert detect_spdx_version(f) == V(2, 3, None, "yaml")


def test_detect_spdx_version_xml(tmp_path):
    f = tmp_path / "sbom.spdx.xml"
    f.write_text("<spdxVersion>SPDX-2.3</spdxVersion>", encoding="utf-8")
    assert detect_spdx_version(f) == V(2, 3, None, "xml")


def test_detect_spdx_version_rdf_xml(tmp_path):
    f = tmp_path / "sbom.spdx.rdf"
    f.write_text("<spdx:specVersion>SPDX-2.3</spdx:specVersion>", encoding="utf-8")
    assert detect_spdx_version(f) == V(2, 3, None, "rdf-xml")


def test_detect_spdx_version_spdx3_jsonld_specversion(tmp_path):
    f = tmp_path / "sbom.spdx.json"
    f.write_text(
        '{"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld",'
        ' "@graph": [{"specVersion": "3.0.1"}]}',
        encoding="utf-8",
    )
    assert detect_spdx_version(f) == V(3, 0, 1, "json-ld")


def test_detect_spdx_version_spdx3_jsonld_context_fallback(tmp_path):
    f = tmp_path / "sbom.spdx.json"
    f.write_text(
        '{"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld", "@graph": []}',
        encoding="utf-8",
    )
    assert detect_spdx_version(f) == V(3, 0, None, "json-ld")


def test_detect_spdx_version_spdx3_turtle_specversion(tmp_path):
    f = tmp_path / "sbom.spdx.ttl"
    f.write_text('spdx:specVersion "3.0.1" ;', encoding="utf-8")
    assert detect_spdx_version(f) == V(3, 0, 1, "turtle")


def test_detect_spdx_version_accepts_str_path(tmp_path):
    f = tmp_path / "sbom.spdx"
    f.write_text("SPDXVersion: SPDX-2.3\n", encoding="utf-8")
    assert detect_spdx_version(str(f)) == V(2, 3, None, "tag-value")


def test_detect_spdx_version_missing_file():
    assert detect_spdx_version("/nonexistent/path/sbom.spdx") is None


def test_detect_spdx_version_non_spdx_file(tmp_path):
    f = tmp_path / "random.txt"
    f.write_text("Hello, world!\n", encoding="utf-8")
    assert detect_spdx_version(f) is None


def test_detect_spdx_version_importable():
    from spdx_python_model import SpdxVersionInfo as SI
    from spdx_python_model import detect_spdx_version as fn

    assert callable(fn)
    assert SI is SpdxVersionInfo
