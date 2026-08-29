#!/usr/bin/env python3
"""In-container empirical feature probe. Writes probe JSON to stdout.

Runs BEFORE the test tier in every lane, as the same unprivileged user
the tests run as. Records what the environment ACTUALLY provides — the
matrix report keys on these probed capabilities, never on lane names.

Probes:
  landlock          raw landlock_create_ruleset(NULL, 0, VERSION) — ABI
                    number or errno; landlock_add_rule(-1,...) errno as a
                    second discriminator (EBADF = implemented, ENOSYS =
                    absent/faked).
  unshare_newuser   unshare(CLONE_NEWUSER) in a forked child.
  clone_newuser     raw clone(CLONE_NEWUSER|SIGCHLD) in a forked child
                    (a seccomp profile may treat clone and unshare
                    differently — probe both).
  mount_in_userns   util-linux `unshare -U -m --map-root-user` + tmpfs
                    mount (the composite the mount-ns lane needs).
  proc_mount_in_userns  `unshare -U -p -m -f --map-root-user
                    --mount-proc` (the fresh-procfs contract).

Plus environment facts: kernel, uid, Seccomp mode, NoNewPrivs, CapEff,
AppArmor label, /proc masking.

stdlib-only; must run on any container python3 (3.12..3.14).
"""

import ctypes
import errno
import json
import os
import platform
import signal
import subprocess
import sys

libc = ctypes.CDLL(None, use_errno=True)

SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_CLONE = 56  # x86_64
CLONE_NEWUSER = 0x10000000
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0


def errno_name(e: int) -> str:
    return errno.errorcode.get(e, f"errno-{e}")


def probe_landlock() -> dict:
    ctypes.set_errno(0)
    r = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0),
                     ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
    out: dict[str, object] = {}
    if r >= 0:
        out["abi"] = int(r)
        out["state"] = "present"
    else:
        e = ctypes.get_errno()
        out["abi"] = None
        out["errno"] = errno_name(e)
        out["state"] = "enosys" if e == errno.ENOSYS else f"err-{errno_name(e)}"
    # Second discriminator: implemented kernels return EBADF for a bogus
    # ruleset fd; a faked/absent syscall returns ENOSYS.
    ctypes.set_errno(0)
    r2 = libc.syscall(SYS_LANDLOCK_ADD_RULE, -1, 0, None, ctypes.c_uint32(0))
    out["add_rule_errno"] = errno_name(ctypes.get_errno()) if r2 < 0 else "ok"
    return out


def _in_child(fn) -> dict:
    """Run fn() in a forked child; child exits with 0 (ok) or errno."""
    pid = os.fork()
    if pid == 0:
        try:
            code = fn()
        except Exception:  # noqa: BLE001
            code = 250
        os._exit(code & 0xFF)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        code = os.WEXITSTATUS(status)
        if code == 0:
            return {"state": "ok"}
        if code >= 250:
            return {"state": "exception"}
        return {"state": "denied", "errno": errno_name(code)}
    return {"state": "signal", "signal": os.WTERMSIG(status)}


def probe_unshare_newuser() -> dict:
    def fn() -> int:
        ctypes.set_errno(0)
        r = libc.unshare(CLONE_NEWUSER)
        return 0 if r == 0 else (ctypes.get_errno() or 251)
    return _in_child(fn)


def probe_clone_newuser() -> dict:
    def fn() -> int:
        ctypes.set_errno(0)
        r = libc.syscall(SYS_CLONE,
                         ctypes.c_ulong(CLONE_NEWUSER | signal.SIGCHLD),
                         None, None, None, ctypes.c_ulong(0))
        if r == 0:
            os._exit(0)  # clone child: leave immediately
        if r > 0:
            try:
                os.waitpid(r, 0)
            except OSError:
                pass
            return 0
        return ctypes.get_errno() or 251
    return _in_child(fn)


def _run(cmd: list) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return {"state": "tool-missing"}
    except subprocess.TimeoutExpired:
        return {"state": "timeout"}
    if p.returncode == 0 and "SXV-OK" in p.stdout:
        return {"state": "ok"}
    return {"state": "fail", "rc": p.returncode,
            "stderr": p.stderr.strip()[-500:]}


def probe_mount_in_userns() -> dict:
    return _run(["unshare", "-U", "-m", "--map-root-user", "sh", "-c",
                 "mount -t tmpfs sxv /mnt && echo SXV-OK"])


def probe_proc_mount_in_userns() -> dict:
    return _run(["unshare", "-U", "-p", "-m", "-f", "--map-root-user",
                 "--mount-proc", "sh", "-c",
                 "cat /proc/self/status >/dev/null && echo SXV-OK"])


def probe_seccomp() -> dict:
    """Functional seccomp probe: libseccomp present AND a minimal
    allow-all filter actually loads (prctl NNP + seccomp_init +
    seccomp_load) in a throwaway child. Filter install is per-task and
    one-way, hence the fork."""
    import ctypes.util
    path = ctypes.util.find_library("seccomp")
    if not path:
        return {"state": "no-libseccomp"}

    def fn() -> int:
        lib = ctypes.CDLL(path, use_errno=True)
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_load.restype = ctypes.c_int
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            return ctypes.get_errno() or 245
        ctx = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
        if not ctx:
            return 246
        rc = lib.seccomp_load(ctx)
        if rc == 0:
            return 0
        e = -rc
        return e if 0 < e < 240 else 247
    return _in_child(fn)


def probe_pivot_root_in_userns() -> dict:
    # docker's default seccomp profile omits pivot_root entirely, so it
    # EPERMs via defaultErrnoRet even with CAP_SYS_ADMIN — this probe
    # separates that from genuine namespace capability. Raw syscall
    # (SYS_pivot_root=155 on x86_64), matching how RAPTOR's rootfs lane
    # calls it — ubuntu 26.04 dropped the pivot_root(8) binary.
    inner = (
        "import ctypes, os, sys\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "r = libc.mount(b'tmpfs', b'/mnt', b'tmpfs', 0, b'mode=755')\n"
        "if r != 0:\n"
        "    sys.exit('mount: ' + os.strerror(ctypes.get_errno()))\n"
        "os.mkdir('/mnt/old')\n"
        "os.chdir('/mnt')\n"
        "r = libc.syscall(155, b'.', b'old')\n"
        "if r != 0:\n"
        "    sys.exit('pivot_root: ' + os.strerror(ctypes.get_errno()))\n"
        "print('SXV-OK')\n"
    )
    return _run(["unshare", "-U", "-m", "--map-root-user",
                 sys.executable, "-c", inner])


def env_facts() -> dict:
    facts = {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "uid": os.getuid(),
        "gid": os.getgid(),
    }
    try:
        for line in open("/proc/self/status"):
            key = line.split(":", 1)[0]
            if key in ("Seccomp", "NoNewPrivs", "CapEff", "CapBnd"):
                facts[key.lower()] = line.split(":", 1)[1].strip()
    except OSError:
        pass
    for path in ("/proc/self/attr/apparmor/current", "/proc/self/attr/current"):
        try:
            facts["apparmor"] = open(path).read().strip()
            break
        except OSError:
            continue
    # docker masks /proc/kcore behind /dev/null unless systempaths=unmasked
    try:
        facts["proc_kcore_masked"] = os.stat("/proc/kcore").st_size == 0 \
            and not os.path.ismount("/proc/kcore")
    except OSError:
        facts["proc_kcore_masked"] = "stat-failed"
    return facts


def shape(res: dict) -> dict:
    """Collapse probe results into the canonical shape the report keys on."""
    ll = res["landlock"]["state"]
    uns, cl = res["unshare_newuser"]["state"], res["clone_newuser"]["state"]
    if uns == "ok" and cl == "ok":
        userns = "ok"
    elif uns != "ok" and cl != "ok":
        userns = "denied"
    else:
        userns = f"mixed(unshare={uns},clone={cl})"
    return {
        "landlock": ll,
        "userns": userns,
        "mount_in_userns": "ok" if res["mount_in_userns"]["state"] == "ok"
        else "fail",
        "proc_mount_in_userns": "ok"
        if res["proc_mount_in_userns"]["state"] == "ok" else "fail",
        "pivot_root_in_userns": "ok"
        if res["pivot_root_in_userns"]["state"] == "ok" else "fail",
        "seccomp": "ok" if res["seccomp"]["state"] == "ok"
        else res["seccomp"].get("state", "fail"),
    }


def main() -> None:
    res = {
        "lane": os.environ.get("SXV_LANE", "?"),
        "env": env_facts(),
        "landlock": probe_landlock(),
        "unshare_newuser": probe_unshare_newuser(),
        "clone_newuser": probe_clone_newuser(),
        "mount_in_userns": probe_mount_in_userns(),
        "proc_mount_in_userns": probe_proc_mount_in_userns(),
        "pivot_root_in_userns": probe_pivot_root_in_userns(),
        "seccomp": probe_seccomp(),
    }
    res["shape"] = shape(res)
    json.dump(res, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
