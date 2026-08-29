#!/bin/sh
# Container entrypoint shim.
#
# The local docker engine rejects `--security-opt systempaths=unmasked`,
# but the kernel refuses a fresh `mount -t proc` inside a user namespace
# while the container's /proc carries docker's masking overmounts (the
# "fully visible" rule). Lanes that model a bare-metal runner therefore
# start as container-root (--user root -e SXV_UNMASK=1), strip the
# masks, and drop to the unprivileged runner user. All other lanes exec
# straight through unchanged.
set -eu

if [ "${SXV_UNMASK:-0}" = "1" ] && [ "$(id -u)" = "0" ]; then
    # docker MaskedPaths (/dev/null and tmpfs overmounts)
    for p in /proc/acpi /proc/kcore /proc/keys /proc/latency_stats \
             /proc/timer_list /proc/timer_stats /proc/sched_debug \
             /proc/scsi /proc/interrupts /sys/firmware \
             /sys/devices/virtual/powercap; do
        umount "$p" 2>/dev/null || true
    done
    # docker ReadonlyPaths (proc-on-proc ro binds — these also violate
    # the fully-visible rule)
    for p in /proc/bus /proc/fs /proc/irq /proc/sys /proc/sysrq-trigger; do
        umount "$p" 2>/dev/null || true
    done
    exec setpriv --reuid runner --regid runner --init-groups \
        env HOME=/home/runner USER=runner LOGNAME=runner \
        /harness/inner-run.sh
fi

exec /harness/inner-run.sh
