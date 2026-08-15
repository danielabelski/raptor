"""Cache-aligned prompt composition (pattern library in system prompt).

When the provider supports prompt caching, the run-stable pattern
material moves from every per-function user prompt into the (cached)
system prompt. These tests pin the three load-bearing properties:
the library is deterministic (byte-identical → cache hits), the user
prompt actually drops the static material (the saving), and dynamic
mid-run primers never migrate into the cached prefix (correctness).
"""

from __future__ import annotations

from core.audit.context import (
    format_context_for_prompt,
    render_pattern_library,
)


def _ctx(**over):
    base = {
        "file": "src/aes_util.c",
        "function": "f",
        "source": "int f(void) { return 1; }",
        "language": "c",
        "line_start": 1,
        "line_end": 1,
        "strategy_primers": ["STATIC PRIMER SENTINEL"],
        "strategy_exemplars": [{
            "cve": "CVE-SENTINEL", "strategy": "memory",
            "title": "t", "reasoning": "r",
        }],
    }
    base.update(over)
    return base


def test_library_is_deterministic_and_substantial():
    lib1 = render_pattern_library()
    lib2 = render_pattern_library()
    assert lib1 == lib2, "cache prefix must be byte-identical across calls"
    assert len(lib1) > 2000
    # One source of truth: the fixed pattern blocks render in the library
    assert "Kernel-internal patterns" in lib1
    assert "Go patterns" in lib1
    assert "Crypto helper patterns" in lib1
    assert "Strategy exemplars" in lib1


def test_default_composition_unchanged():
    p = format_context_for_prompt(_ctx())
    assert "STATIC PRIMER SENTINEL" in p
    assert "CVE-SENTINEL" in p
    assert "Crypto helper patterns" in p


def test_patterns_in_system_drops_static_material():
    p = format_context_for_prompt(_ctx(), patterns_in_system=True)
    assert "STATIC PRIMER SENTINEL" not in p
    assert "CVE-SENTINEL" not in p
    assert "Crypto helper patterns" not in p
    # the function's own content is untouched
    assert "src/aes_util.c:f" in p
    assert "int f(void)" in p


def test_dynamic_primers_stay_in_user_prompt():
    ctx = _ctx(dynamic_primers=["DYNAMIC PRIMER SENTINEL"])
    ctx["strategy_primers"] = [
        "STATIC PRIMER SENTINEL", "DYNAMIC PRIMER SENTINEL",
    ]
    p = format_context_for_prompt(ctx, patterns_in_system=True)
    assert "DYNAMIC PRIMER SENTINEL" in p
    assert "STATIC PRIMER SENTINEL" not in p


def test_dynamic_primers_never_in_library():
    # The library is built from static registries only — nothing
    # run-discovered may enter the cached prefix.
    lib = render_pattern_library()
    assert "DYNAMIC" not in lib


def test_kernel_blocks_gated():
    ctx = _ctx(file="drivers/net/foo.c",
               source="static int f(void) { spin_lock(&l); return 0; }",
               kernel_style=True)
    p_default = format_context_for_prompt(dict(ctx))
    p_system = format_context_for_prompt(dict(ctx), patterns_in_system=True)
    if "Kernel-internal patterns" in p_default:
        assert "Kernel-internal patterns" not in p_system
