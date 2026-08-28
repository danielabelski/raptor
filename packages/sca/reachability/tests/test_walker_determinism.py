"""Walk order must be stable across hosts/filesystems.

Raw ``os.walk`` order is readdir-dependent; unsorted walks made the
capped reachability evidence lists differ between runs of the same
tree, churning corpus refresh diffs.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.reachability._walker import walk_source_files


def test_walk_returns_lexicographic_order(tmp_path: Path) -> None:
    for rel in (
        "zeta/mod.go", "zeta/alpha.go", "alpha/z.go", "alpha/a.go",
        "beta.go", "aardvark.go",
    ):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("package x\n")
    files = [
        str(path.relative_to(tmp_path))
        for path, _suffix in walk_source_files(tmp_path)
    ]
    assert files == [
        "aardvark.go", "beta.go",
        "alpha/a.go", "alpha/z.go",
        "zeta/alpha.go", "zeta/mod.go",
    ]
