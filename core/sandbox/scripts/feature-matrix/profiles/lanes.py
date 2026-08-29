#!/usr/bin/env python3
"""Lane definitions: docker security options + intended feature shape.

Single source of truth, consumed two ways:
  * run-matrix.sh:   python3 profiles/lanes.py args <lane> --profiles DIR
                     -> newline-separated docker run arguments
  * bin/report.py:   imports LANES and compares each lane's probed
                     shape against `expect` (None = record-only lane,
                     no divergence check — "probe, don't assume").

Design notes
------------
All custom-profile lanes share apparmor=unconfined + CAP_SYS_ADMIN +
root-entry /proc unmasking so that exactly ONE variable — the seccomp
profile — differs between them. Rationale:

  * apparmor=unconfined: Ubuntu's docker-default AppArmor profile denies
    mount(2) even inside a fully-owned user namespace, which would fuse
    the mount/procfs probe results across lanes and mask the seccomp
    variable under test.
  * --user root + SXV_UNMASK=1 (see bin/entry.sh): docker's masked
    /proc paths make procfs "not fully visible", so the kernel refuses
    fresh `mount -t proc` inside a user namespace regardless of
    permissions. The local engine rejects `systempaths=unmasked`
    (verified empirically), so the entry shim unmounts the masks as
    container-root and drops to the runner user. Restores the
    bare-metal runner shape the lanes are modelling.
  * CAP_SYS_ADMIN: the moby default profile only installs its
    unshare/clone/clone3 allow group when the container has
    CAP_SYS_ADMIN in its bounding set (the cap gates which *rules* are
    compiled in, not per-process privilege); it also legalises the
    unmask step. Tests still run as the unprivileged uid-1001 runner
    user, which holds no capabilities.

`default` is stock docker confinement — no overrides, no expectations;
the probe records what it actually blocks.
"""

import argparse
import sys

LANE_ORDER = ["full", "default", "no-landlock", "no-userns", "no-both"]

_COMMON = [
    "--security-opt", "apparmor=unconfined",
    "--cap-add", "SYS_ADMIN",
    "--user", "root",
    "-e", "SXV_UNMASK=1",
]

LANES: dict[str, dict[str, object]] = {
    "full": {
        "docker_args": ["--privileged"],
        "expect": {"landlock": "present", "userns": "ok",
                   "mount_in_userns": "ok", "proc_mount_in_userns": "ok",
                   "pivot_root_in_userns": "ok", "seccomp": "ok"},
        "intent": "namespaces AND Landlock available",
    },
    "default": {
        "docker_args": [],
        "expect": None,  # probe, don't assume
        "intent": "stock docker confinement (empirical)",
    },
    # no-landlock mirrors `full` in every respect except the faked-away
    # Landlock syscalls (allow-all seccomp base + cap-add ALL), so its
    # failure delta against `full` isolates pure Landlock absence.
    "no-landlock": {
        "docker_args": ["--security-opt", "seccomp=@PROFILES@/no-landlock.json",
                        "--security-opt", "apparmor=unconfined",
                        "--cap-add", "ALL",
                        "--user", "root", "-e", "SXV_UNMASK=1"],
        "expect": {"landlock": "enosys", "userns": "ok",
                   "mount_in_userns": "ok", "proc_mount_in_userns": "ok",
                   "pivot_root_in_userns": "ok", "seccomp": "ok"},
        "intent": "pre-5.13-kernel fake: namespaces yes, Landlock ENOSYS",
    },
    "no-userns": {
        "docker_args": ["--security-opt", "seccomp=@PROFILES@/no-userns.json",
                        *_COMMON],
        "expect": {"landlock": "present", "userns": "denied",
                   "mount_in_userns": "fail", "proc_mount_in_userns": "fail",
                   "pivot_root_in_userns": "fail", "seccomp": "ok"},
        "intent": "userns denied (EPERM), Landlock present",
    },
    "no-both": {
        "docker_args": ["--security-opt", "seccomp=@PROFILES@/no-both.json",
                        *_COMMON],
        "expect": {"landlock": "enosys", "userns": "denied",
                   "mount_in_userns": "fail", "proc_mount_in_userns": "fail",
                   "pivot_root_in_userns": "fail", "seccomp": "ok"},
        "intent": "no namespaces, no Landlock",
    },
}


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_args = sub.add_parser("args")
    p_args.add_argument("lane", choices=LANE_ORDER)
    p_args.add_argument("--profiles", required=True,
                        help="directory holding the generated seccomp JSONs")
    sub.add_parser("list")
    ns = ap.parse_args()

    if ns.cmd == "list":
        print("\n".join(LANE_ORDER))
        return
    lane = LANES[ns.lane]
    args = lane["docker_args"]
    assert isinstance(args, list)
    for a in args:
        sys.stdout.write(a.replace("@PROFILES@", ns.profiles) + "\n")


if __name__ == "__main__":
    main()
