#ifdef __AMIGA__
char const * sshDir = "envarc:";
char const * sshDotDir = "envarc:.ssh";
char const * keyFile;
#else
#include "amiemul.h"

extern "C" char* concat(const char *s0, ...) {
    if (!s0) return 0;
    size_t sz = 1 + strlen(s0);
    va_list args;
    va_start(args, s0);
    for(;;) {
        char const *s = va_arg(args, char const*);
        if (!s)
            break;
        sz += strlen(s);
    }
    va_end(args);
    char * r = (char *)malloc(sz);
    if (!r) return 0;

    char * q = r;
    va_start(args, s0);
    while ((*q = *s0++)) {
        ++q;
    }
    for(;;) {
        char const *s = va_arg(args, char const*);
        if (!s)
            break;
        while ((*q = *s++)) {
            ++q;
        }
    }
    va_end(args);
    return r;
}

char const * sshDir = "";
char const * sshDotDir = "";
char const * keyFile;
static struct __ {
    __() {
        sshDir = concat(getenv("HOME"), "/", NULL);
        sshDotDir = concat(sshDir, ".ssh", NULL);
    }
} __;

#endif
