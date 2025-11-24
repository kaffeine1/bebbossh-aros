/*
 * crypto logging interface
 * Copyright (C) 1998, 2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide logging interface with configurable debug levels.
 *
 * Features:
 *  - Enum of debug levels (NONE -> ULTRA)
 *  - Functions to set and query current log level
 *  - Variadic log function with printf-style formatting
 *  - Parse log level from string input
 *
 * Notes:
 *  - C linkage provided for C++ compatibility
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __LOG_H__
#define __LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

/// Debug levels for logging
enum DebugLevel {
    L_NONE,
    L_FATAL,
    L_ERROR,
    L_WARN,
    L_INFO,
    L_DEBUG,
    L_FINE,
    L_TRACE,
    L_ULTRA
};

/// Set the current log level
void setLogLevel(enum DebugLevel lvl);

/// Query whether a given log level is active
short isLogLevel(enum DebugLevel lvl);

/// Log a message with printf-style formatting
extern void logme(enum DebugLevel lvl, char const* fmt, ...);

/// Parse a log level from string (e.g. "INFO", "DEBUG")
extern void parseLogLevel(char const* l);

#ifdef __cplusplus
}
#endif

#endif // __LOG_H__
