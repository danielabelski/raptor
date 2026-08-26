---
description: Generate secure patches for vulnerabilities (beta)
dispatch: python3 raptor.py agentic
---

# /patch - Generate Secure Patches (beta)

Generate secure patches to fix vulnerabilities.

**Requires:** a target repository (agentic re-scans it, or pass `--sarif <file>` to reuse findings from a previous /scan)

**What it does:**
- Analyzes findings with LLM
- Generates secure patch code
- Saves to out/*/autonomous/patches/
- Does NOT generate exploits (use /exploit for that)

**Run:** `python3 raptor.py agentic --repo <path> --no-exploits --max-findings <N>`

**Example:**
```bash
/scan test/                    # First, find vulnerabilities
/patch                         # Then, generate fixes for findings
```

**Note:** Review patches before applying to production code.

**Dynamic verification:** when the finding has a PoC input and you can
build both the original and patched source, verify the patch at
runtime: `libexec/raptor-frida-patch-verify --before <orig-binary>
--after <patched-binary> --sink <sink-fn> --poc <input>
[--location FILE:LINE]`. See the Patch Verification section of
[docs/frida.md](../../docs/frida.md).

---
