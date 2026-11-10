/*
 * aros_noposixc - the posixc.library functions of the AROS aarch64 build
 * Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>
 * Author: Michele Dipace (@kaffeine1)
 *
 * GNU GPL v3 or later, see COPYING.
 *
 * The aarch64 build does not link posixc.library: every program that opens
 * it loses about 160 KB when it ends, because the library opens stdc.library
 * and stdcio.library for itself and does not close them.
 */
#include <proto/dos.h>
#include <dos/dos.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>

/* AmigaDOS counts from 1978, time_t from 1970: 2922 days. */
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	struct DateStamp ds;

	(void)tz;
	if (!tv)
		return -1;

	DateStamp(&ds);
	tv->tv_sec = (ds.ds_Days + 2922) * 86400 + ds.ds_Minute * 60
			+ ds.ds_Tick / TICKS_PER_SECOND;
	tv->tv_usec = (ds.ds_Tick % TICKS_PER_SECOND) * (1000000 / TICKS_PER_SECOND);
	return 0;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	struct tm *t = gmtime(timep);

	if (!t)
		return 0;
	*result = *t;
	return result;
}

int mkdir(const char *path, mode_t mode)
{
	BPTR lock = CreateDir((CONST_STRPTR)path);

	(void)mode;
	if (!lock)
		return -1;
	UnLock(lock);
	return 0;
}
