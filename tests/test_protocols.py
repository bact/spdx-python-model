# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0
#
# Every generated version's concrete classes must satisfy the protocols under
# strict mypy, and all versions must unify under the one structural type. The set
# of generated versions varies by build (draft versions such as v3_1 are not
# always present), so the probe is built from the versions actually present.

from __future__ import annotations

import ast
import sys
import warnings
from pathlib import Path
from typing import Optional

import pytest

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
DATA_DIR = Path(__file__).parent / "data"

# Well-known classes spanning Core, Software, SimpleLicensing, and
# ExpandedLicensing profiles; each version's instances must satisfy the
# corresponding protocol.  Profile classes carry a prefix in the bindings
# (e.g. software_Package).
_CLASSES = [
    "Person",
    "Element",
    "ElementCollection",
    "SpdxDocument",
    "CreationInfo",
    "Relationship",
    "RelationshipType",
    "IndividualElement",
    "software_Package",
    "software_Sbom",
    "simplelicensing_AnyLicenseInfo",
    "expandedlicensing_IndividualLicensingInfo",
    "expandedlicensing_License",
]

# Named-individual IRI constants (str) that must exist, as (owning class, attr).
_NAMED_INDIVIDUALS = [
    ("IndividualElement", "NoneElement"),
    ("IndividualElement", "NoAssertionElement"),
    ("expandedlicensing_IndividualLicensingInfo", "NoAssertionLicense"),
    ("expandedlicensing_IndividualLicensingInfo", "NoneLicense"),
]


def _available_versions() -> list[str]:
    """Module names (e.g. 'v3_0_1') of every generated version binding."""
    import spdx_python_model.bindings as bindings

    pkg_dir = Path(bindings.__file__).resolve().parent
    return sorted(
        p.name
        for p in pkg_dir.iterdir()
        if p.is_dir() and p.name.startswith("v") and (p / "model.py").exists()
    )


_MACHINERY = {"SHACLObjectProtocol", "SHACLObjectSetProtocol"}


def _domain_class_names(version: str) -> set[str]:
    """Domain Protocol class names defined by one version's protocols.py.

    Mirrors gen/generate-protocols._domain_class_names(), so this test checks
    the same class set the merge script itself works from.
    """
    import spdx_python_model.bindings as bindings

    pkg_dir = Path(bindings.__file__).resolve().parent
    tree = ast.parse((pkg_dir / version / "protocols.py").read_text())
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name not in _MACHINERY
    }


def _build_probe(versions: list[str]) -> str:
    lines = [
        "from typing import Any, List, Optional",
        "from spdx_python_model import SpdxModelModule, SpdxObject, SpdxObjectSet",
        "from spdx_python_model import protocols",
    ]
    for v in versions:
        lines.append(f"from spdx_python_model.bindings import {v}")
    lines += [
        "",
        "def count(s: SpdxObjectSet) -> int:",
        "    return sum(1 for _ in s.foreach())",
        "",
    ]

    for v in versions:
        lines += [
            f"# --- {v} ---",
            f"module_{v}: SpdxModelModule = {v}",
            f"objset_{v}: SpdxObjectSet = {v}.SHACLObjectSet()",
            f"count(objset_{v})",
            f"count(module_{v}.SHACLObjectSet())",
            f"module_{v}.SHACLObjectSet().add(module_{v}.Person())",
            f"prerelease_{v}: bool = module_{v}.IS_PRERELEASE",
        ]
        for i, cls in enumerate(_CLASSES):
            lines.append(f"c{i}_{v}: protocols.{cls} = {v}.{cls}()")
        for i, (cls, name) in enumerate(_NAMED_INDIVIDUALS):
            lines.append(f"n{i}_{v}: str = {v}.{cls}.{name}")
        lines.append("")

    lines += [
        "def relabel(e: protocols.Element, ci: protocols.CreationInfo) -> Optional[str]:",
        "    e.name = 'renamed'",
        "    e.creationInfo = ci",
        "    return e.name",
        "",
    ]
    for v in versions:
        lines.append(f"relabel({v}.Person(), {v}.CreationInfo())")

    all_sets = ", ".join(f"objset_{v}" for v in versions)
    lines += [
        "",
        f"every: List[SpdxObjectSet] = [{all_sets}]",
        "for _s in every:",
        "    count(_s)",
        "",
    ]
    return "\n".join(lines)


def test_strict_mypy_protocols_satisfied_by_all_versions(tmp_path: Path) -> None:
    from mypy import api

    versions = _available_versions()
    assert versions, "no generated version bindings found"

    probe = tmp_path / "probe.py"
    probe.write_text(_build_probe(versions))

    stdout, stderr, status = api.run(
        ["--config-file", str(PYPROJECT), "--strict", str(probe)]
    )
    assert status == 0, stdout + stderr


def test_class_introduced_in_later_version_is_included_from_that_version(
    tmp_path: Path,
) -> None:
    """A class introduced in a later version resolves from that version."""
    from mypy import api

    versions = _available_versions()
    if len(versions) < 2:
        pytest.skip("need >= 2 generated versions to test a later-introduced class")

    baseline, *later = versions
    baseline_names = _domain_class_names(baseline)

    new_class = None
    introducing_version = None
    for v in later:
        only_in_v = sorted(_domain_class_names(v) - baseline_names)
        if only_in_v:
            new_class = only_in_v[0]
            introducing_version = v
            break

    if new_class is None:
        pytest.skip("no version-specific class found across generated versions")

    from spdx_python_model import protocols

    proto_cls = getattr(protocols, new_class)
    assert proto_cls.__module__ == (
        f"spdx_python_model.bindings.{introducing_version}.protocols"
    ), (
        f"{new_class!r} is only defined in {introducing_version!r}, but "
        f"protocols.{new_class} resolves to {proto_cls.__module__!r} "
        "instead of that version's protocols module"
    )

    probe = tmp_path / "later_version_class.py"
    probe.write_text(
        "\n".join(
            [
                "from spdx_python_model import protocols",
                f"from spdx_python_model.bindings import {introducing_version}",
                "",
                f"x: protocols.{new_class} = "
                f"{introducing_version}.{new_class}()",
                "",
            ]
        )
    )

    stdout, stderr, status = api.run(
        ["--config-file", str(PYPROJECT), "--strict", str(probe)]
    )
    assert status == 0, stdout + stderr


def test_loaded_objset_is_usable_through_protocol() -> None:
    import spdx_python_model
    from spdx_python_model import SpdxObjectSet

    _model, objset = spdx_python_model.load(
        DATA_DIR / "3.0.1" / "example.spdx3.json"
    )

    def names(s: SpdxObjectSet) -> list[Optional[str]]:
        return [o.get_id() for o in s.foreach_type("Person")]

    assert isinstance(list(objset.foreach()), list)
    assert names(objset) is not None
    assert objset.find_by_id("does-not-exist", None) is None


def test_is_prerelease_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """is_prerelease_version() reflects module.IS_PRERELEASE."""
    from spdx_python_model import is_prerelease_version
    from spdx_python_model.bindings import v3_0_1

    monkeypatch.setattr(v3_0_1, "IS_PRERELEASE", False)
    assert is_prerelease_version(v3_0_1) is False

    monkeypatch.setattr(v3_0_1, "IS_PRERELEASE", True)
    assert is_prerelease_version(v3_0_1) is True


def test_is_prerelease_version_does_not_load_model() -> None:
    """Reading IS_PRERELEASE must not import model.py."""
    if "v3_1" not in _available_versions():
        pytest.skip("v3_1 binding not generated")

    for mod in list(sys.modules):
        if mod == "spdx_python_model.bindings.v3_1" or mod.startswith(
            "spdx_python_model.bindings.v3_1."
        ):
            del sys.modules[mod]

    from spdx_python_model import is_prerelease_version
    from spdx_python_model.bindings import v3_1

    is_prerelease_version(v3_1)
    assert "spdx_python_model.bindings.v3_1.model" not in sys.modules


def test_draft_warning_on_version_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """SPDXDraftWarning fires on spdx_python_model.<version> access iff IS_PRERELEASE."""
    import spdx_python_model
    from spdx_python_model import SPDXDraftWarning
    from spdx_python_model.bindings import v3_0_1

    monkeypatch.setattr(v3_0_1, "IS_PRERELEASE", True)
    with pytest.warns(SPDXDraftWarning):
        spdx_python_model.v3_0_1

    monkeypatch.setattr(v3_0_1, "IS_PRERELEASE", False)
    with warnings.catch_warnings():
        warnings.simplefilter("error", SPDXDraftWarning)
        spdx_python_model.v3_0_1


def test_draft_warning_on_load(monkeypatch: pytest.MonkeyPatch) -> None:
    """load() raises SPDXDraftWarning iff the document's version is IS_PRERELEASE."""
    import spdx_python_model
    from spdx_python_model import SPDXDraftWarning
    from spdx_python_model.bindings import v3_0_1

    example = DATA_DIR / "3.0.1" / "example.spdx3.json"

    monkeypatch.setattr(v3_0_1, "IS_PRERELEASE", False)
    with warnings.catch_warnings():
        warnings.simplefilter("error", SPDXDraftWarning)
        spdx_python_model.load(example)

    monkeypatch.setattr(v3_0_1, "IS_PRERELEASE", True)
    with pytest.warns(SPDXDraftWarning):
        spdx_python_model.load(example)


def test_draft_warning_attributed_to_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    """SPDXDraftWarning attributes to the caller for attribute access and load_data()."""
    import json

    import spdx_python_model
    from spdx_python_model.bindings import v3_0_1

    monkeypatch.setattr(v3_0_1, "IS_PRERELEASE", True)
    example = DATA_DIR / "3.0.1" / "example.spdx3.json"
    data = json.loads(example.read_text())

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        spdx_python_model.v3_0_1
    assert caught[0].filename == __file__

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        spdx_python_model.load_data(data)
    assert caught[0].filename == __file__


def test_draft_versions_symbol_removed() -> None:
    """bindings/__init__.py must not define _DRAFT_VERSIONS."""
    import spdx_python_model.bindings as bindings

    assert not hasattr(bindings, "_DRAFT_VERSIONS")
