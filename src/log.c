/*
 * crypto logging utility
 * Copyright (C) 2024-2025  Stefan Franke <stefan@franke.ms>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version (GPLv3+).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Module: log.c / log.cpp
 *
 * Purpose:
 *  - Provide portable logging with severity levels (FATAL, ERROR, WARN, INFO, DEBUG, FINE, TRACE)
 *  - Print timestamps and log level names
 *  - Support Amiga custom chip timing and POSIX clock() timing
 *
 * Notes:
 *  - Global DEBUG_LEVEL pointer controls current verbosity
 *  - parseLogLevel() maps string names to enum DebugLevel
 *  - logme() prints formatted messages if level <= current DEBUG_LEVEL
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#if defined(__AMIGA__) || defined(__AROS__)
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#include <sys/time.h>
#endif

#include <stdarg.h>
#include <string.h>
#include <time.h>

#define __IN_CRYPTOSSH_LIBRARY
#include "log.h"

static char const * LEVELNAMES[] = {"", "FATAL", "ERROR", "WARN ", "INFO ", "DEBUG", "FINE ", "TRACE", "ULTRA"};

enum DebugLevel DEBUG_LEVEL__data = L_WARN;
enum DebugLevel * DEBUG_LEVEL = &DEBUG_LEVEL__data;

void logme(enum DebugLevel lvl, char const *fmt, ...) {
	if (lvl <= *DEBUG_LEVEL) {
		va_list args;
		va_start(args, fmt);
		time_t ti = 0;
		int ms = 0;
#if defined(__AROS__)
		struct DateStamp ds;
		DateStamp(&ds);
		ms = (ds.ds_Tick % TICKS_PER_SECOND) * 20;
		fprintf(stderr, "[aros:%ld.%02ld.%03d] [%s] ", ds.ds_Days, ds.ds_Minute, ms, LEVELNAMES[lvl]);
		vfprintf(stderr, fmt, args);
		fputs("\r\n", stderr);
		va_end(args);
		fflush(stderr);
		return;
#elif defined(__AMIGA__)
		static volatile struct Custom * c = (struct Custom *)0xdff000;
		static int lastms;
		static int lastvp;
		static time_t lastti;
		struct DateStamp ds;
		DateStamp(&ds); /* Get timestamp */
		ti = ((ds.ds_Days + 2922) * 1440 + ds.ds_Minute /* + timezone*/) * 60 + ds.ds_Tick / TICKS_PER_SECOND;
		ms = (ds.ds_Tick % TICKS_PER_SECOND) * 20;
		int vp = (c->vhposr >> 8);
		if (ti == lastti && ms == lastms) {
			if (vp < lastvp)
				vp = lastvp;
			if (vp >> 4 >= 20)
				vp = 19 << 4;
		} else
			vp = 0;

		lastti = ti;
		lastms = ms;
		lastvp = vp;
		ms += vp >> 4;
#else
	    struct timeval tv;
	    gettimeofday(&tv, NULL);

	    ti = tv.tv_sec;                 // proper wall-clock seconds
	    ms = tv.tv_usec / 1000;         // milliseconds (0...999)
#endif
		struct tm const  * t = gmtime(&ti);
		fprintf(stderr, "[%04ld.%02ld.%02ld-%02ld:%02ld:%02ld.%03ld] [%s] ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, ms, LEVELNAMES[lvl]);
		vfprintf(stderr, fmt, args);
		fputs("\r\n", stderr);
		va_end(args);
		fflush(stderr);
	}
}

void parseLogLevel(char const * l) {
	if (0 == strcasecmp("none", l))
		setLogLevel(L_NONE);
	else if (0 == strcasecmp("error", l))
		setLogLevel(L_ERROR);
	else if (0 == strcasecmp("warn", l))
		setLogLevel(L_WARN);
	else if (0 == strcasecmp("info", l))
		setLogLevel(L_INFO);
	else if (0 == strcasecmp("debug", l))
		setLogLevel(L_DEBUG);
	else if (0 == strcasecmp("fine", l))
		setLogLevel(L_FINE);
	else if (0 == strcasecmp("trace", l))
		setLogLevel(L_TRACE);
	else if (0 == strcasecmp("ultra", l))
		setLogLevel(L_ULTRA);
	else
		logme(L_ERROR, "invalid logme level %s", l);
}

void setLogLevel(enum DebugLevel lvl) {
	*DEBUG_LEVEL = lvl;
	if (isLogLevel(L_INFO))
		printf("loglevel %ld\n", lvl);
}

short isLogLevel(enum DebugLevel lvl) {
	return *DEBUG_LEVEL >= lvl;
}
