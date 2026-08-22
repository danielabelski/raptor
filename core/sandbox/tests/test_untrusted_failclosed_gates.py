"""Fail-closed preflight gates for the untrusted/strict contracts.

Two silent-degradation seams:

- On macOS, _require_userns_or_optin returned False unconditionally
  ("the seatbelt tier provides the isolation contract there") without
  verifying seatbelt actually engages — with sandbox-exec missing or
  smoke-failing, run_untrusted's default profile warned once and ran
  attacker-derived code as a bare subprocess. Only strict aborted.
- strict's preflight checked namespaces/mount only; with libseccomp
  absent the filter builder returns None and both spawn paths run
  filterless (AF_UNIX blocklist, io_uring/keyring/bpf, UDP block all
  gone) under a profile sold as fail-closed.
"""

import sys
import tempfile
import unittest
from unittest.mock import patch

import core.sandbox.context as ctx
from core.sandbox.errors import SandboxSetupError


class TestDarwinUntrustedGate(unittest.TestCase):
    """Unit-level: the darwin arm of _require_userns_or_optin."""

    def _call(self):
        return ctx._require_userns_or_optin("run_untrusted()",
                                            restrict_reads=True)

    def test_darwin_with_seatbelt_available_is_exempt(self):
        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=True):
            self.assertFalse(self._call())

    def test_darwin_without_seatbelt_fails_closed(self):
        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=False), \
             patch.dict(ctx.os.environ,
                        {"RAPTOR_ALLOW_DEGRADED_UNTRUSTED": ""}):
            with self.assertRaises(SandboxSetupError):
                self._call()

    def test_darwin_operator_override_engages_degraded_mode(self):
        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=False), \
             patch.dict(ctx.os.environ,
                        {"RAPTOR_ALLOW_DEGRADED_UNTRUSTED": "1"}):
            self.assertFalse(self._call())


class TestStrictRequiresSeccomp(unittest.TestCase):
    def setUp(self):
        if sys.platform != "linux":
            self.skipTest("Linux strict gate")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_strict_aborts_when_libseccomp_unavailable(self):
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False):
            with self.assertRaises(SandboxSetupError) as cm:
                with ctx.sandbox(profile="strict",
                                 target=self.tmp.name,
                                 output=self.tmp.name):
                    pass
            self.assertIn("seccomp", str(cm.exception).lower())

    def test_full_profile_still_degrades_gracefully(self):
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False):
            # construction must not raise for the degrading profile
            with ctx.sandbox(profile="full", target=self.tmp.name,
                             output=self.tmp.name):
                pass


if __name__ == "__main__":
    unittest.main()


class TestUntrustedRequiresSeccomp(unittest.TestCase):
    """The untrusted preflight must refuse to run attacker-derived
    code FILTERLESS: with libseccomp absent, the AF_UNIX blocklist,
    escape-primitive blocks and send-flag argument rules all silently
    vanish — previously only strict aborted; run_untrusted degraded
    with a warning."""

    def _call(self):
        return ctx._require_userns_or_optin("run_untrusted()",
                                            restrict_reads=True)

    def test_linux_without_libseccomp_fails_closed(self):
        if sys.platform != "linux":
            self.skipTest("Linux gate")
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False), \
             patch.dict(ctx.os.environ,
                        {"RAPTOR_ALLOW_DEGRADED_UNTRUSTED": ""}):
            with self.assertRaises(SandboxSetupError) as cm:
                self._call()
            self.assertIn("seccomp", str(cm.exception).lower())

    def test_operator_override_engages_degraded_mode(self):
        if sys.platform != "linux":
            self.skipTest("Linux gate")
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False), \
             patch.dict(ctx.os.environ,
                        {"RAPTOR_ALLOW_DEGRADED_UNTRUSTED": "1"}):
            self._call()  # must not raise

    def test_darwin_arm_untouched_by_seccomp_gate(self):
        """macOS has no libseccomp; the seatbelt arm must return
        before the seccomp gate is consulted."""
        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=True), \
             patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False):
            self.assertFalse(self._call())
