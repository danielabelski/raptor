/* Minimal rustup-proxy emulation: re-exec the same-named binary from
 * the $HOME toolchain dir, like rustup's ~/.cargo/bin shims do. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    const char *base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];
    char buf[4096];
    snprintf(buf, sizeof buf,
             "/home/runner/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/%s",
             base);
    execv(buf, argv);
    perror(buf);
    return 127;
}
