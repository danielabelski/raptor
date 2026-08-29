"""Host-layout leak scrub for sandboxed children.

A sandboxed child's environment used to reveal the host layout and
identity even when every filesystem layer hid it:

- OLDPWD carried the orchestrator's previous working directory
  (typically the RAPTOR checkout path) through get_safe_env().
- PWD carried the orchestrator's cwd.
- PATH kept home-rooted entries (~/.local/bin, ~/bin) that name the
  operator's home while pointing at directories the sandbox cannot
  read anyway.
- USER/LOGNAME kept the operator's login name even under fake_home,
  where the child is deliberately told it lives somewhere else.
- With no cwd= the Landlock-only subprocess path started the child in
  the ORCHESTRATOR's cwd (host-layout leak; relative writes landed in
  the driver's directory), while the mount-ns path started in "/".

These tests pin the scrubbed shapes end-to-end through sandbox().run()
and at the get_safe_env() unit level.
"""

import json
import os
import sys
import tempfile
import unittest

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="sandbox env scrub paths are Linux-only",
)

_DUMP = (
    "import json, os; "
    "print(json.dumps({'cwd': os.getcwd(), 'env': dict(os.environ)}))"
)


def _run_and_dump(**sandbox_kwargs):
    from core.sandbox import sandbox

    with sandbox(**sandbox_kwargs) as run:
        r = run(
            [sys.executable, "-c", _DUMP],
            capture_output=True, text=True, timeout=60,
        )
    assert r.returncode == 0, f"dump child failed: {r.stderr!r}"
    return json.loads(r.stdout.strip().splitlines()[-1])


class TestGetSafeEnvOldpwd(unittest.TestCase):
    def test_oldpwd_never_in_safe_env(self):
        from core.config import RaptorConfig
        old = os.environ.get("OLDPWD")
        os.environ["OLDPWD"] = "/somewhere/revealing"
        try:
            env = RaptorConfig.get_safe_env()
            self.assertNotIn("OLDPWD", env)
        finally:
            if old is None:
                os.environ.pop("OLDPWD", None)
            else:
                os.environ["OLDPWD"] = old


class TestSandboxedChildLayoutScrub(unittest.TestCase):
    """End-to-end: the child env/cwd reveal no host layout/identity."""

    def setUp(self):
        self._out = tempfile.TemporaryDirectory(prefix="raptor-envscrub-")
        self.addCleanup(self._out.cleanup)
        self.out = os.path.realpath(self._out.name)

    def _dump(self, **kw):
        kw.setdefault("output", self.out)
        return _run_and_dump(**kw)

    def test_no_oldpwd_or_pwd(self):
        env = self._dump()["env"]
        self.assertNotIn("OLDPWD", env)
        self.assertNotIn("PWD", env)

    def test_path_has_no_home_rooted_entries(self):
        env = self._dump()["env"]
        home = os.path.expanduser("~")
        for comp in env.get("PATH", "").split(os.pathsep):
            self.assertFalse(
                comp.startswith("/home/")
                or comp == home
                or comp.startswith(home + os.sep),
                f"home-rooted PATH entry leaked into sandboxed child: "
                f"{comp!r}",
            )

    def test_declared_tool_path_survives_home_scrub(self):
        """A home-rooted PATH entry under a DECLARED tool_paths dir must
        stay in the child PATH: the same declaration binds the dir into
        the mount view and grants it to Landlock, and dropping the PATH
        entry left the declared tool unresolvable by name (execvp
        ENOENT, exit 127 — the rustup ~/.cargo/bin failure shape).
        Undeclared home-rooted entries keep getting scrubbed."""
        home = os.path.expanduser("~")
        try:
            holder = tempfile.TemporaryDirectory(
                prefix=".toolseam-", dir=home)
        except OSError:
            self.skipTest("home directory not writable")
        self.addCleanup(holder.cleanup)
        tooldir = os.path.join(holder.name, "bin")
        os.makedirs(tooldir)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = tooldir + os.pathsep + old_path
        self.addCleanup(os.environ.__setitem__, "PATH", old_path)

        env = self._dump()["env"]
        self.assertNotIn(
            tooldir, env.get("PATH", "").split(os.pathsep),
            "undeclared home-rooted PATH entry survived the scrub")

        env = self._dump(tool_paths=[tooldir])["env"]
        self.assertIn(
            tooldir, env.get("PATH", "").split(os.pathsep),
            "declared tool_paths dir was scrubbed out of the child PATH")

    def test_default_cwd_is_output_dir(self):
        dump = self._dump()
        self.assertEqual(
            os.path.realpath(dump["cwd"]), self.out,
            "sandboxed child with no cwd= must start in the output dir, "
            "not the orchestrator's cwd",
        )

    def test_caller_cwd_still_wins(self):
        with tempfile.TemporaryDirectory(prefix="raptor-cwd-") as want:
            # cwd must be visible inside the sandbox: pass it as target.
            from core.sandbox import sandbox
            with sandbox(output=self.out, target=want) as run:
                r = run(
                    [sys.executable, "-c", _DUMP],
                    cwd=want, capture_output=True, text=True, timeout=60,
                )
            assert r.returncode == 0, r.stderr
            dump = json.loads(r.stdout.strip().splitlines()[-1])
            self.assertEqual(
                os.path.realpath(dump["cwd"]), os.path.realpath(want),
            )

    def test_fake_home_neutralises_user_identity(self):
        env = self._dump(fake_home=True)["env"]
        self.assertEqual(env.get("USER"), "sandbox")
        self.assertEqual(env.get("LOGNAME"), "sandbox")

    def test_gate_divergent_bare_name_refused_naming_both(self):
        """venv-shaped divergence: ~/.venv-style pip in the caller PATH
        plus a same-named system-side pip in the child's surviving PATH
        must REFUSE with both resolutions named — never quietly exec
        the system copy."""
        from core.sandbox import SandboxSetupError, sandbox
        venv_bin, sys_bin = self._divergent_pip_dirs()
        with sandbox(output=self.out) as run:
            with pytest.raises(SandboxSetupError) as exc:
                run(["pip", "--version"],
                    capture_output=True, text=True, timeout=60)
        msg = str(exc.value)
        assert os.path.join(venv_bin, "pip") in msg
        assert os.path.join(sys_bin, "pip") in msg
        assert "tool_paths" in msg

    def test_gate_declared_tool_paths_runs_the_caller_pip(self):
        """Declared via tool_paths= the DECLARED (venv-shaped) pip runs
        — proven by its marker, not just a zero exit."""
        from core.sandbox import sandbox
        venv_bin, _sys_bin = self._divergent_pip_dirs()
        with sandbox(output=self.out, tool_paths=[venv_bin]) as run:
            r = run(["pip", "--version"],
                    capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, (r.returncode, r.stderr[-300:])
        assert "venv-pip-marker" in r.stdout

    def test_gate_opt_out_runs_the_child_resolution(self):
        """allow_path_divergence=True is the explicit intent statement:
        the child's own (scrubbed) PATH resolution runs."""
        from core.sandbox import sandbox
        _venv_bin, _sys_bin = self._divergent_pip_dirs()
        with sandbox(output=self.out) as run:
            r = run(["pip", "--version"], allow_path_divergence=True,
                    capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, (r.returncode, r.stderr[-300:])
        assert "system-pip-marker" in r.stdout

    def test_gate_absolute_path_untouched(self):
        """Absolute-path invocations never consult PATH — no gate."""
        from core.sandbox import sandbox
        venv_bin, sys_bin = self._divergent_pip_dirs()
        with sandbox(output=self.out) as run:
            r = run([os.path.join(sys_bin, "pip"), "--version"],
                    capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, (r.returncode, r.stderr[-300:])
        assert "system-pip-marker" in r.stdout

    def test_gate_same_resolution_untouched(self):
        """A bare name resolving identically on both sides passes."""
        from core.sandbox import sandbox
        _venv_bin, sys_bin = self._divergent_pip_dirs()
        with sandbox(output=self.out) as run:
            r = run(["sametool"],
                    capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, (r.returncode, r.stderr[-300:])
        assert "same-tool-marker" in r.stdout

    def test_gate_untrusted_refuses_by_default(self):
        """run_untrusted: divergence refusal is on by default."""
        from core.sandbox import SandboxSetupError, check_net_available
        from core.sandbox.context import run_untrusted
        if not check_net_available():
            pytest.skip("User namespaces not available")
        self._divergent_pip_dirs()
        with pytest.raises(SandboxSetupError, match="resolves to"):
            run_untrusted(["pip", "--version"],
                          target=self.out, output=self.out,
                          capture_output=True, text=True, timeout=60)

    def _divergent_pip_dirs(self):
        """Build the venv-shaped divergence: a home-resident bin dir
        (scrubbed from the child PATH) and a sandbox-visible bin dir
        (under the output dir, which is bound at its original path),
        each holding a marker `pip`; PATH = venv:system:original."""
        home = os.path.expanduser("~")
        try:
            holder = tempfile.TemporaryDirectory(
                prefix=".venvseam-", dir=home)
        except OSError:
            pytest.skip("home directory not writable")
        self.addCleanup(holder.cleanup)
        venv_bin = os.path.join(holder.name, "venv", "bin")
        os.makedirs(venv_bin)
        sys_bin = os.path.join(self.out, "sysbin")
        os.makedirs(sys_bin, exist_ok=True)
        for d, marker in ((venv_bin, "venv-pip-marker"),
                          (sys_bin, "system-pip-marker")):
            p = os.path.join(d, "pip")
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"#!/bin/sh\necho {marker}\n")
            os.chmod(p, 0o755)
        same = os.path.join(sys_bin, "sametool")
        with open(same, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho same-tool-marker\n")
        os.chmod(same, 0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = os.pathsep.join([venv_bin, sys_bin, old_path])
        self.addCleanup(os.environ.__setitem__, "PATH", old_path)
        return venv_bin, sys_bin

    def test_caller_env_still_verbatim(self):
        """Caller-supplied env= is documented pass-through — the scrub
        must not touch it."""
        from core.sandbox import sandbox
        caller_env = {
            "PATH": "/usr/bin:/bin",
            "PWD": "/kept/verbatim",
            "OLDPWD": "/kept/verbatim/too",
        }
        with sandbox(output=self.out) as run:
            r = run(
                [sys.executable, "-c", _DUMP],
                env=caller_env, env_caller_filtered=True,
                capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(r.returncode, 0, r.stderr)
        env = json.loads(r.stdout.strip().splitlines()[-1])["env"]
        self.assertEqual(env.get("PWD"), "/kept/verbatim")
        self.assertEqual(env.get("OLDPWD"), "/kept/verbatim/too")


if __name__ == "__main__":
    unittest.main()
