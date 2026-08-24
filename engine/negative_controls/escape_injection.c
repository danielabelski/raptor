/* Negative control: "terminal escape" / "escape sequence" keyword
 * family (CWE-150).
 *
 * The canonical safe idiom — sanitize control characters INTO a
 * buffer (strnvis), then print the buffer — is textually identical
 * to the unsafe print at the printf site. The pattern therefore
 * matches this guarded fixture by design (presence-style), and the
 * sweep caps the dynamic rule at inconclusive: a printf-%s match
 * alone can never confirm escape injection. Confirmation-grade
 * evidence comes from the joern taint leg.
 */
#include <stdio.h>

extern int strnvis(char *dst, const char *src, size_t dlen, int flag);

void show_name(const char *untrusted_name)
{
    char vbuf[1024];

    strnvis(vbuf, untrusted_name, sizeof(vbuf), 0);
    printf("%s\n", vbuf); /* vbuf is already sanitized */
}
