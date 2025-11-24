/*
 * bebbossh - configuration line parser
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
 * Project: bebbossh - SSH2 client/server suite for Amiga
 * Purpose: Parse configuration file lines into key/value pairs
 *
 * Features:
 *  - Trim whitespace and ignore empty lines
 *  - Skip comments beginning with '#'
 *  - Extract first word and its parameter
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS; integrates with project logging facilities.
 *
 * Author's intent:
 *  Provide a simple, maintainable parser for configuration files
 *  with clear logging of skipped or malformed lines.
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include "log.h"

char * splitLine(char * & s) {
	int len = strlen((char *)s);
	while (len > 0 && s[--len] <= ' ')
		s[len] = 0;

	// find start
	while (*s && *s <= ' ')
		++s;

	// comment
	if (*s == '#') {
		logme(L_TRACE, "skip comment %s", s);
		return 0;
	}

	// find end of first word
	char * e = s;
	while (*e && *e > ' ')
		++e;

	if (e == s) {
		logme(L_TRACE, "skip empty line");
		return 0;
	}

	// find start of parameter
	char *p = e;
	while (*p && *p <= ' ')
		++p;

	if (p == e) {
		logme(L_WARN, "missing parameter in `%s`", s);
		return 0;
	}
	*e = 0;
	return p;
}
