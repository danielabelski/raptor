#!/usr/bin/env python3
"""Derive lane seccomp profiles from docker's default profile JSON.

Input: profiles/moby-default-seccomp-v28.3.0.json (pinned copy of
moby/moby profiles/seccomp/default.json at tag v28.3.0 — the closest
published tag to the local docker engine; later tags 404 on raw
githubusercontent at fetch time).

Outputs (into --out DIR):
  no-landlock.json  allow-all base (defaultAction SCMP_ACT_ALLOW, arch
                    map copied from the default profile) with
                    landlock_create_ruleset / landlock_add_rule /
                    landlock_restrict_self as an explicit
                    SCMP_ACT_ERRNO(ENOSYS=38) group — a faithful fake of
                    a pre-5.13 bare-metal kernel (probe sees ENOSYS, not
                    EPERM; pivot_root/mount/unshare all work, unlike the
                    docker default profile which omits pivot_root and so
                    EPERMs it via defaultErrnoRet even with
                    CAP_SYS_ADMIN — verified empirically). This keeps
                    the lane a SINGLE-variable diff against `full`.
  no-userns.json    default profile with unshare/clone/clone3 removed
                    from every group, then:
                      * unshare/clone with CLONE_NEWUSER (0x10000000) in
                        the flags arg -> EPERM (SCMP_CMP_MASKED_EQ)
                      * unshare/clone without CLONE_NEWUSER -> allow
                      * clone3 -> ENOSYS(38) unconditionally, forcing
                        libc fallback to clone (clone3's flags live in
                        user memory and cannot be seccomp-filtered)
                    s390/s390x carry clone's flags in arg1; mirrored for
                    completeness even though this harness is x86_64.
  no-both.json      composition of the two transforms.
"""

import argparse
import copy
import json
from pathlib import Path

LANDLOCK_SYSCALLS = [
    "landlock_add_rule",
    "landlock_create_ruleset",
    "landlock_restrict_self",
]
USERNS_SYSCALLS = ["clone", "clone3", "unshare"]
CLONE_NEWUSER = 0x10000000
ENOSYS = 38
EPERM = 1


def _strip_names(profile: dict, names: list[str]) -> None:
    """Remove the given syscall names from every group; drop empty groups."""
    kept = []
    for group in profile["syscalls"]:
        group["names"] = [n for n in group["names"] if n not in names]
        if group["names"]:
            kept.append(group)
    profile["syscalls"] = kept


def no_landlock_allow_all(profile: dict) -> dict:
    """Pre-5.13-kernel fake: everything allowed except landlock_* -> ENOSYS."""
    return {
        "defaultAction": "SCMP_ACT_ALLOW",
        "archMap": copy.deepcopy(profile.get("archMap", [])),
        "syscalls": [{
            "names": list(LANDLOCK_SYSCALLS),
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": ENOSYS,
        }],
    }


def strip_landlock(profile: dict) -> dict:
    """Default-profile variant of the landlock transform (used for the
    no-both composition, where docker-profile realism is kept because
    the userns denial dominates anyway)."""
    p = copy.deepcopy(profile)
    _strip_names(p, LANDLOCK_SYSCALLS)
    p["syscalls"].append({
        "names": list(LANDLOCK_SYSCALLS),
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": ENOSYS,
    })
    return p


def no_userns(profile: dict) -> dict:
    p = copy.deepcopy(profile)
    _strip_names(p, USERNS_SYSCALLS)
    masked = lambda index, datum: [{  # noqa: E731
        "index": index,
        "value": CLONE_NEWUSER,      # mask
        "valueTwo": datum,           # expected (arg & mask)
        "op": "SCMP_CMP_MASKED_EQ",
    }]
    p["syscalls"] += [
        # x86_64 (and everything but s390*): flags in arg0 for both.
        {"names": ["clone", "unshare"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(0, CLONE_NEWUSER),
         "excludes": {"arches": ["s390", "s390x"]}},
        {"names": ["clone", "unshare"], "action": "SCMP_ACT_ALLOW",
         "args": masked(0, 0),
         "excludes": {"arches": ["s390", "s390x"]}},
        # s390*: clone flags in arg1; unshare stays arg0.
        {"names": ["clone"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(1, CLONE_NEWUSER),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["clone"], "action": "SCMP_ACT_ALLOW",
         "args": masked(1, 0),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["unshare"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(0, CLONE_NEWUSER),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["unshare"], "action": "SCMP_ACT_ALLOW",
         "args": masked(0, 0),
         "includes": {"arches": ["s390", "s390x"]}},
        # clone3 cannot be arg-filtered; ENOSYS forces libc's clone path.
        {"names": ["clone3"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": ENOSYS},
    ]
    return p


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=str(
        Path(__file__).parent / "moby-default-seccomp-v28.3.0.json"))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    base = json.loads(Path(args.base).read_text())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, prof in (
        ("no-landlock", no_landlock_allow_all(base)),
        ("no-userns", no_userns(base)),
        ("no-both", no_userns(strip_landlock(base))),
    ):
        (out / f"{name}.json").write_text(json.dumps(prof, indent=1) + "\n")
        print(f"wrote {out / f'{name}.json'}")


if __name__ == "__main__":
    main()
