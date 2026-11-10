/*
 * <time.h> for the AROS aarch64 build without posixc.library: the stdc
 * header plus gmtime_r(), which is in src/aros_noposixc.c.
 */
#ifndef BEBBOSSH_NOPOSIXC_TIME_H
#define BEBBOSSH_NOPOSIXC_TIME_H

#include_next <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tm *gmtime_r(const time_t *timep, struct tm *result);

#ifdef __cplusplus
}
#endif

#endif
