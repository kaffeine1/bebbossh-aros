/*
 * crypto hex dump utility (_dump)
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
 * Purpose: Provide a simple hex dump function for debugging binary data.
 *
 * Features:
 *  - Prints data in hex with ASCII side view
 *  - Groups output in 16-byte rows with offset
 *  - Amiga builds use <amistdio.h>, others use <stdio.h>
 *
 * Notes:
 *  - Useful for debugging cryptographic buffers and protocol messages
 * ----------------------------------------------------------------------
 */

#include <inttypes.h>
#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif

void _dump(char const *txt, void const *_data, unsigned len) {
    uint8_t *data = (uint8_t*) _data;
    char s[18];
    s[0] = ' ';
    s[17] = 0;
    unsigned int i = 0;
    int j = 1;
    printf("%s: length = %ld", txt, len);
    for (; i < len; ++i, ++j) {
        if (j == 1) {
            printf("\n%04lx", i);
            fflush(stdout);
        }
        putchar(' ');
        int c = data[i];
        int x = (c & 0xff) >> 4;
        if (x > 9)
            putchar((char) (55 + x));
        else
            putchar((char) (48 + x));

        x = (c & 0xf);
        if (x > 9)
            putchar((char) (55 + x));
        else
            putchar((char) (48 + x));

        if (c < 32 || c > 127)
            c = '.';
        s[j] = c;

        if (j == 16) {
            printf(" %s", s);
            fflush(stdout);
            j = 0;
        } else if (j == 8)
            putchar(' ');
    }
    if (j) {
        s[j] = 0;
        if (j < 9)
            putchar(' ');

        while (++j <= 17)
            printf("   ");
        printf(" %s", s);
    }
    fflush(stdout);
    puts("");
}
