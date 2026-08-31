"""Tests for the libFuzzer runner process contract."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.fuzzing.libfuzzer_runner import LibFuzzerRunner


class TestLibFuzzerRunner(unittest.TestCase):

    def test_run_uses_sandbox_and_sanitised_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            out_dir = tmp / "out"

            captured = {}

            def fake_sandbox_run(cmd, **kwargs):
                captured["cmd"] = cmd
                captured["kwargs"] = kwargs

                class Result:
                    returncode = 0
                    stdout = ""
                    stderr = "#1 DONE cov: 1 ft: 1 corp: 1/1b exec/s: 1\n"

                return Result()

            with patch.dict(os.environ, {"LD_PRELOAD": "evil.dylib"}, clear=False), \
                 patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                       side_effect=fake_sandbox_run):
                runner = LibFuzzerRunner(
                    harness_path=harness,
                    output_dir=out_dir,
                    max_total_time=1,
                )
                result = runner.run()

            self.assertEqual(result.stats.total_executions, 1)
            self.assertEqual(captured["cmd"][0], str(harness.resolve()))
            self.assertTrue(captured["kwargs"]["block_network"])
            self.assertTrue(captured["kwargs"]["restrict_reads"])
            self.assertNotIn("LD_PRELOAD", captured["kwargs"]["env"])
            # identity scrub: the harness is untrusted target code
            env = captured["kwargs"]["env"]
            for ident in ("USER", "LOGNAME", "HOSTNAME", "PWD"):
                self.assertNotIn(ident, env)
            self.assertEqual(env.get("HOME"), "/tmp")
            self.assertEqual(captured["kwargs"]["output"], str(out_dir.resolve()))

    def test_corpus_is_copied_into_output_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            seed_dir = tmp / "seeds"
            seed_dir.mkdir()
            (seed_dir / "seed0").write_bytes(b"seed")

            runner = LibFuzzerRunner(
                harness_path=harness,
                corpus_dir=seed_dir,
                output_dir=tmp / "out",
                max_total_time=1,
            )

            self.assertEqual((runner.corpus_dir / "seed0").read_bytes(), b"seed")
            self.assertTrue(str(runner.corpus_dir).startswith(str((tmp / "out").resolve())))

    def test_default_output_dir_anchored_to_configured_out_dir(self):
        # Regression: the default output dir was a literal
        # `out/libfuzzer_*` relative to the CWD at construction time,
        # planting run dirs inside whatever directory the operator
        # launched from instead of the configured run base.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            configured = tmp / "configured-out"

            with patch(
                "core.config.RaptorConfig.get_out_dir",
                return_value=configured,
            ):
                runner = LibFuzzerRunner(harness_path=harness)

            self.assertTrue(
                str(runner.output_dir).startswith(str(configured.resolve())),
                f"default output dir {runner.output_dir} not under the "
                f"configured out dir {configured}",
            )


class TestSeedWorkingCorpusSymlinks(unittest.TestCase):
    """Corpus seeding must never dereference symlinks: a hostile
    in-repo corpus can plant ``seed -> <host secret>`` and the copied
    bytes would be handed to the untrusted harness and persisted in
    run artifacts. Mirrors the AFL corpus stager's contract."""

    def test_file_symlink_rejected_regular_files_copied(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            secret = tmp / "secret"
            secret.write_bytes(b"PRIVATE-KEY-MATERIAL")
            source = tmp / "corpus"
            (source / "nested").mkdir(parents=True)
            (source / "seed-real").write_bytes(b"A")
            (source / "nested" / "seed-deep").write_bytes(b"B")
            (source / "seed-link").symlink_to(secret)
            dest = tmp / "dest"
            dest.mkdir()

            LibFuzzerRunner._seed_working_corpus(source, dest)

            self.assertEqual((dest / "seed-real").read_bytes(), b"A")
            self.assertEqual(
                (dest / "nested" / "seed-deep").read_bytes(), b"B")
            self.assertFalse((dest / "seed-link").exists())
            copied = {p.read_bytes() for p in dest.rglob("*") if p.is_file()}
            self.assertNotIn(b"PRIVATE-KEY-MATERIAL", copied)

    def test_directory_symlink_not_traversed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            outside = tmp / "outside"
            outside.mkdir()
            (outside / "leak").write_bytes(b"OUTSIDE")
            source = tmp / "corpus"
            source.mkdir()
            (source / "seed0").write_bytes(b"A")
            (source / "dirlink").symlink_to(outside)
            dest = tmp / "dest"
            dest.mkdir()

            LibFuzzerRunner._seed_working_corpus(source, dest)

            self.assertEqual((dest / "seed0").read_bytes(), b"A")
            self.assertFalse((dest / "dirlink").exists())


if __name__ == "__main__":
    unittest.main()
