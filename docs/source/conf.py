# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0
"""
Sphinx configuration for API documentation
"""

import os
import sys

# Add project src to sys.path so Sphinx can import the package
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
)

project = "spdx-python-model"
author = "SPDX"

# Prefer environment `VERSION` (set by CI), fall back to package
env_version = os.environ.get("VERSION")
if env_version:
    version = env_version
    release = env_version
else:
    try:
        from spdx_python_model.version import VERSION as pkg_version

        version = pkg_version
        release = pkg_version
    except Exception:
        version = "0.0.0"
        release = version

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
]

autosummary_generate = True
exclude_patterns = ["_build"]

html_theme = "pydata_sphinx_theme"
html_theme_options = {
    "navbar_end": ["version-switcher", "navbar-icon-links"],
    "switcher": {
        # The theme will fetch this JSON to populate the version dropdown.
        "json_url": "https://bact.github.io/spdx-python-model/versions.json",
        # Match the current built version so the correct entry is selected
        "version_match": version,
    },
}
html_static_path = ["_static"]

autodoc_member_order = "bysource"
autodoc_typehints = "description"

master_doc = "index"
