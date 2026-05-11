#ifndef BEBBOSSH_PLATFORM_H
#define BEBBOSSH_PLATFORM_H

#if defined(__AROS__)
#define BEBBOSSH_AROS 1
#else
#define BEBBOSSH_AROS 0
#endif

#if defined(__AMIGA__) || BEBBOSSH_AROS
#define BEBBOSSH_AMIGA_API 1
#else
#define BEBBOSSH_AMIGA_API 0
#endif

#if BEBBOSSH_AROS
#ifndef __stdargs
#define __stdargs
#endif
#ifndef __far
#define __far
#endif
#ifndef __saveds
#define __saveds
#endif

static inline char *utoa(unsigned int value, char *buf, int base) {
    static const char digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char tmp[32];
    int i = 0;
    if (base < 2 || base > 36) {
        buf[0] = '\0';
        return buf;
    }
    do {
        tmp[i++] = digits[value % base];
        value /= base;
    } while (value && i < (int)sizeof(tmp));
    int j = 0;
    while (i--) buf[j++] = tmp[i];
    buf[j] = '\0';
    return buf;
}

#ifdef __cplusplus
extern "C" char* concat(const char *s0, ...);
#endif
#endif

#if defined(__linux__)
#define BEBBOSSH_LINUX 1
#else
#define BEBBOSSH_LINUX 0
#endif

#if BEBBOSSH_LINUX
#define BEBBOSSH_PAM_AUTH 1
#define BEBBOSSH_POSIX_SHELL 1
#else
#define BEBBOSSH_PAM_AUTH 0
#define BEBBOSSH_POSIX_SHELL 0
#endif

#endif
