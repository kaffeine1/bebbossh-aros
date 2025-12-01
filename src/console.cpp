/*
 * AmigaSSH - Console support
 *
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
 * Project: AmigaSSH - SSH2 client/server suite for Amiga
 * Purpose: console support
 *
 * Features:
 *  - get console size etc.
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management.
 *
 * Author's intent:
 *  Provide clear, maintainable definitions for keyboard qualifier handling
 *  to support SSH client/server input processing on Amiga systems.
 * ----------------------------------------------------------------------
 */

#include <stdint.h>

#ifdef __AMIGA__
#include <proto/dos.h>
#else
#include "amiemul.h"
#endif

BPTR stdinBptr;
BPTR stdoutBptr;

uint32_t numCols;
uint32_t numRows;


bool getConsoleSize() {
#ifdef __AMIGA__
    // --- Amiga code as you already have ---
    uint8_t tmp[16];
    if (!stdoutBptr)
        return false;
    Write(stdinBptr, "\x9b\x30\x20\x71", 4);
    uint8_t *p = &tmp[0];
    while (WaitForChar(stdinBptr, 200) == DOSTRUE) {
        Read(stdinBptr, p, 1);
        ++p;
        if (p > &tmp[15])
            break;
    }
    uint8_t *q = &tmp[5];
    numRows = 0;
    for (; q < p; ++q) {
        if (*q == ';')
            break;
        numRows = numRows * 10 + (*q - '0');
    }
    ++q;
    numCols = 0;
    for (; q < p; ++q) {
        if (*q == ' ')
            break;
        numCols = numCols * 10 + (*q - '0');
    }
    return true;

#elif defined(__linux__) || defined(__unix__)
    // --- Linux/Unix: use ioctl TIOCGWINSZ ---
    #include <sys/ioctl.h>
    #include <unistd.h>
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1)
        return false;
    numRows = ws.ws_row;
    numCols = ws.ws_col;
    return true;

#elif defined(_WIN32)
    // --- Windows: use GetConsoleScreenBufferInfo ---
    #include <windows.h>
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleScreenBufferInfo(hOut, &csbi))
        return false;
    numCols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    numRows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    return true;

#else
    return false;
#endif
}
