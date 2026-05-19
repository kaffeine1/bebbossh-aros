#ifndef BEBBOSSH_COMPAT_AMISTDIO_H
#define BEBBOSSH_COMPAT_AMISTDIO_H

#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT)
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int printf(const char *fmt, ...);
int puts(const char *s);
int putchar(int c);
int fflush(void *stream);
int snprintf(char *buf, size_t size, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#define stdin ((void *)0)
#define stdout ((void *)0)
#define stderr ((void *)0)
#elif defined(__AROS__)
#include <stdio.h>
#else
#include_next <amistdio.h>
#endif

#endif
