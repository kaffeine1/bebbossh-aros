#ifndef BEBBOSSH_COMPAT_FNMATCH_H
#define BEBBOSSH_COMPAT_FNMATCH_H

#if !defined(__AROS__)
#include_next <fnmatch.h>
#else

#define FNM_NOMATCH 1
#define FNM_IGNORECASE 0x01

#ifdef __cplusplus
extern "C" {
#endif

int fnmatch(const char *pattern, const char *string, int flags);

#ifdef __cplusplus
}
#endif

#endif

#endif
