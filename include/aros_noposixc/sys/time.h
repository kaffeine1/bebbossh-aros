/*
 * <sys/time.h> for the AROS aarch64 build without posixc.library:
 * struct timeval, the timer macros and gettimeofday(), which is in
 * src/aros_noposixc.c.
 */
#ifndef BEBBOSSH_NOPOSIXC_SYS_TIME_H
#define BEBBOSSH_NOPOSIXC_SYS_TIME_H

#include <aros/types/timeval_s.h>

struct timezone;

#ifndef timercmp
#define timercmp(a, b, cmp) \
	(((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec cmp (b)->tv_usec) : ((a)->tv_sec cmp (b)->tv_sec))
#endif
#ifndef timersub
#define timersub(a, b, res) \
	do { \
		(res)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
		(res)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
		if ((res)->tv_usec < 0) { \
			--(res)->tv_sec; \
			(res)->tv_usec += 1000000; \
		} \
	} while (0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

int gettimeofday(struct timeval *tv, struct timezone *tz);

#ifdef __cplusplus
}
#endif

#endif
