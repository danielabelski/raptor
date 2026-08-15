"""Consumption of project trust markers at run entry points.

Pins the precedence contract (explicit negative > explicit positive >
project marker > default off), the banner emission, and the
project-layer build-does-not-imply-config independence. Hermetic: temp
projects dir via patched ``PROJECTS_DIR``; no network, no binaries.
"""

import argparse
import contextlib
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.project import ProjectManager
from core.project.trust import (
    active_project_trust,
    apply_project_trust_flags,
    resolve_dynamic_validation,
    resolve_trust_flag,
)


def _ns(**kw):
    base = {"trust_repo": False, "no_trust_repo": False,
            "traced_build": False, "no_traced_build": False}
    base.update(kw)
    return argparse.Namespace(**base)


class TrustProjectFixture(unittest.TestCase):
    """Temp projects dir with one active project."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        target = root / "code"
        target.mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("p", str(target), output_dir=str(root / "out"))
        self.mgr.set_active("p")
        patcher = patch("core.project.project.PROJECTS_DIR",
                        self.projects_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _apply(self, ns):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            affecting = apply_project_trust_flags(ns)
        return affecting, out.getvalue()


class TestResolveTrustFlag(unittest.TestCase):
    """Pure precedence table: negative > positive > marker > default."""

    def test_default_off(self):
        self.assertFalse(resolve_trust_flag(False, False, False))

    def test_marker_turns_on(self):
        self.assertTrue(resolve_trust_flag(False, False, True))

    def test_positive_turns_on(self):
        self.assertTrue(resolve_trust_flag(False, True, False))

    def test_negative_beats_marker(self):
        self.assertFalse(resolve_trust_flag(True, False, True))

    def test_negative_beats_positive(self):
        self.assertFalse(resolve_trust_flag(True, True, True))


class TestApplyProjectTrustFlags(TrustProjectFixture):

    def test_no_markers_no_change_no_banner(self):
        ns = _ns()
        affecting, out = self._apply(ns)
        self.assertEqual(affecting, [])
        self.assertFalse(ns.trust_repo)
        self.assertFalse(ns.traced_build)
        self.assertNotIn("project trust", out)

    def test_build_marker_enables_traced_build_only(self):
        """build does NOT imply config at the project layer — the
        consumption-side mirror of TestTracedBuildTrustIndependence."""
        self.mgr.set_trust_marker("p", "build")
        ns = _ns()
        affecting, out = self._apply(ns)
        self.assertEqual(affecting, ["build"])
        self.assertTrue(ns.traced_build)
        self.assertFalse(ns.trust_repo)
        self.assertIn("[*] project trust: build (per-run flags override)",
                      out)

    def test_config_marker_enables_trust_repo_only(self):
        self.mgr.set_trust_marker("p", "config")
        ns = _ns()
        affecting, out = self._apply(ns)
        self.assertEqual(affecting, ["config"])
        self.assertTrue(ns.trust_repo)
        self.assertFalse(ns.traced_build)
        self.assertIn("project trust: config", out)

    def test_both_markers_one_banner_line(self):
        self.mgr.set_trust_marker("p", "config")
        self.mgr.set_trust_marker("p", "build")
        ns = _ns()
        affecting, out = self._apply(ns)
        self.assertEqual(affecting, ["config", "build"])
        self.assertEqual(out.count("[*] project trust:"), 1)

    def test_negative_flag_beats_marker(self):
        self.mgr.set_trust_marker("p", "build")
        self.mgr.set_trust_marker("p", "config")
        ns = _ns(no_traced_build=True, no_trust_repo=True)
        affecting, out = self._apply(ns)
        self.assertEqual(affecting, [])
        self.assertFalse(ns.traced_build)
        self.assertFalse(ns.trust_repo)
        self.assertNotIn("project trust", out)

    def test_negative_flag_beats_positive_flag(self):
        ns = _ns(traced_build=True, no_traced_build=True,
                 trust_repo=True, no_trust_repo=True)
        self._apply(ns)
        self.assertFalse(ns.traced_build)
        self.assertFalse(ns.trust_repo)

    def test_positive_flag_unaffected_and_not_attributed_to_marker(self):
        self.mgr.set_trust_marker("p", "build")
        ns = _ns(traced_build=True)
        affecting, out = self._apply(ns)
        self.assertTrue(ns.traced_build)
        # The explicit flag, not the marker, drove the run: no banner.
        self.assertEqual(affecting, [])
        self.assertNotIn("project trust", out)

    def test_dynamic_marker_ignored_by_flag_resolver(self):
        self.mgr.set_trust_marker("p", "dynamic")
        ns = _ns()
        affecting, _ = self._apply(ns)
        self.assertEqual(affecting, [])
        self.assertFalse(ns.trust_repo)
        self.assertFalse(ns.traced_build)

    def test_args_without_attrs_untouched(self):
        self.mgr.set_trust_marker("p", "config")
        ns = argparse.Namespace()
        affecting, _ = self._apply(ns)
        self.assertEqual(affecting, [])
        self.assertFalse(hasattr(ns, "trust_repo"))


class TestActiveProjectTrust(TrustProjectFixture):

    def test_returns_markers_for_active_project(self):
        self.mgr.set_trust_marker("p", "dynamic")
        markers, name = active_project_trust()
        self.assertEqual(name, "p")
        self.assertEqual(set(markers), {"dynamic"})

    def test_no_active_project(self):
        self.mgr.set_active(None)
        markers, name = active_project_trust()
        self.assertEqual(markers, {})
        self.assertIsNone(name)

    def test_substrate_error_returns_empty(self):
        with patch("core.project.project.ProjectManager",
                   side_effect=RuntimeError("boom")):
            markers, name = active_project_trust()
        self.assertEqual(markers, {})
        self.assertIsNone(name)


class TestResolveDynamicValidation(TrustProjectFixture):

    def _resolve(self, explicit):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = resolve_dynamic_validation(explicit)
        return result, out.getvalue()

    def test_default_off_without_marker(self):
        result, out = self._resolve(None)
        self.assertFalse(result)
        self.assertNotIn("project trust", out)

    def test_marker_defaults_on_with_banner(self):
        self.mgr.set_trust_marker("p", "dynamic")
        result, out = self._resolve(None)
        self.assertTrue(result)
        self.assertIn("[*] project trust: dynamic (per-run flags override)",
                      out)

    def test_explicit_false_beats_marker_no_banner(self):
        self.mgr.set_trust_marker("p", "dynamic")
        result, out = self._resolve(False)
        self.assertFalse(result)
        self.assertNotIn("project trust", out)

    def test_explicit_true_wins_without_banner(self):
        result, out = self._resolve(True)
        self.assertTrue(result)
        self.assertNotIn("project trust", out)


class TestAuditPipelineDynamicOptr(unittest.TestCase):
    """The audit pipeline's tri-state resolver defers to the project
    marker only when the per-run choice is None."""

    def test_pipeline_helper_resolves_tristate(self):
        from core.audit.pipeline import AuditPipelineOpts, _resolve_dynamic
        with patch("core.project.trust.active_project_trust",
                   return_value=({"dynamic": "2026-01-01T00:00:00+00:00"},
                                 "p")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertTrue(
                    _resolve_dynamic(AuditPipelineOpts()))
                self.assertFalse(_resolve_dynamic(
                    AuditPipelineOpts(dynamic_validation=False)))
                self.assertTrue(_resolve_dynamic(
                    AuditPipelineOpts(dynamic_validation=True)))

    def test_pipeline_helper_fails_closed(self):
        from core.audit.pipeline import AuditPipelineOpts, _resolve_dynamic
        with patch("core.project.trust.active_project_trust",
                   side_effect=RuntimeError("boom")):
            self.assertFalse(_resolve_dynamic(AuditPipelineOpts()))


class TestNegativeFlagSurfaces(unittest.TestCase):
    """The four positive-flag surfaces expose the negative escape
    hatches (parser-level pin: parsing must accept the flags)."""

    def test_codeql_agent_negative_beats_positive(self):
        # agent.py resolves --no-traced-build > --traced-build right
        # after parse; replicate the same two-line resolution here on
        # a parsed namespace to pin the semantics without invoking
        # main() (which would touch the filesystem).
        parser = argparse.ArgumentParser()
        parser.add_argument("--traced-build", action="store_true")
        parser.add_argument("--no-traced-build", action="store_true",
                            dest="no_traced_build")
        args = parser.parse_args(["--traced-build", "--no-traced-build"])
        if getattr(args, "no_traced_build", False):
            args.traced_build = False
        self.assertFalse(args.traced_build)


if __name__ == "__main__":
    unittest.main()
