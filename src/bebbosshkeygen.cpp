/*
 * amigasshkeygen - ED25519 key generator
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
 * Project: bebbossh - SSH key utilities for Amiga
 * Purpose: Generate ED25519 key pairs in OpenSSH format
 *
 * Features:
 *  - Private key output with MIME encoding
 *  - Public key generation for authorized_keys
 *  - Interactive overwrite protection
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Outputs to ENVARC:.ssh/id_ed25519 by default.
 *
 * Author's intent:
 *  Provide Amiga developers with a native tool to generate secure SSH keys.
 * ----------------------------------------------------------------------
 */
#define REPLACE_STDIO
#include <amistdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <ed25519.h>
#include <mime.h>
#include <test.h>
#include "revision.h"

#include <proto/dos.h>
#include <proto/exec.h>

static char const *filename = "ENVARC:.ssh/id_ed25519";
static char outfilename[256];

static void printUsage() {
	puts(__VERSION);
	puts("USAGE: amigasshkeygen [-f <output_keyfile>]");
	puts("    -?\tdisplay this help");
}

static void parseParams(unsigned argc, char **argv) {
	char *arg = 0;
	int normal = 0;

	for (unsigned i = 1; i < argc; ++i) {
		arg = argv[i];
		if (arg[0] == '-') {
			switch (arg[1]) {
			case '?':
				goto usage;
			case 'f':
				if (arg[2])
					goto invalid;

				if (i + 1 == argc)
					goto missing;
				strcpy(outfilename, argv[++i]);
				continue;
			default:
				goto invalid;
			}
		}
		++normal;
	}
	if (normal)
		puts("ignoring additional arguments");
	return;

	usage: printUsage();
	exit(0);

	missing: printf("missing parameter for %s\r\n", arg);
	exit(10);

	invalid: printf("invalid option %s\r\n", arg);
	exit(10);
}

__stdargs int main(int argc, char **argv) {
	static char buf[256];

	strcpy(outfilename, filename);

	parseParams(argc, argv);

	// remove the program arguments from stdin
	FGetC(stdin);
	fflush(stdin);

	puts("Generating public/private ed25519 key pair");

	if (0 == strcmp(outfilename, filename)) {
		printf("Enter file in which to save the key (%s): ", outfilename);
		fflush(stdout);
		gets(buf, 255);
		if (*buf > 32) {
			char *p = buf;
			for (; *p > ' '; ++p)
				;
			*p = 0;
			strcpy(outfilename, buf);
		}
	}

	BPTR xist = Open(outfilename, MODE_OLDFILE);
	if (xist) {
		Close(xist);
		printf("%s already exists.\nOverwrite (y/n)? ", outfilename);
		static char buf2[4];
		fflush(stdout);
		gets(buf2, 3);
		if (*buf2 != 'y' && *buf2 != 'Y')
			return 0;
	}

	static uint8_t pk[32];
	static uint8_t sk[64];
	ge_new_keypair_ed25519(pk, sk);

	static char gfx[9][20];
	memset(gfx, ' ', sizeof(gfx));
	for (int i = 0; i < 32; ++i) {
		uint16_t z0 = pk[i];
		uint16_t z = z0;
		int x = z % 9;
		z = z / 9;
		int y = 1 + z % 17;
		z /= 17;
		if (i == 0)
			gfx[x][y] = 'S';
		else if (i == 31) {
			if (gfx[x][y] != 'S')
				gfx[x][y] = 'E';
			else
				gfx[x ? x - 1 : 8][y] = 'E';
		} else if (gfx[x][y] == ' ') {
			if (z)
				gfx[x][y] = (z0 & 1) ? '=' : '+';
			else
				gfx[x][y] = (z0 & 1) ? '.' : 'o';
		}
	}
	puts("+--[ED25519 256]--+");
	for (int i = 0; i < 9; ++i) {
		gfx[i][0] = '|';
		gfx[i][19] = '|';
		gfx[i][20] = 0;
		puts(gfx[i]);
	}
	puts("+----[SHA256]-----+");

	BPTR out = Open(outfilename, MODE_NEWFILE);
	if (!out) {
		char * p = outfilename + strlen(outfilename);
		while (p > outfilename) {
			--p;
			if (*p == '/' || *p == ':')
				break;
		}
		if (p > outfilename) {
			char c = *p;
			*p = 0;
			mkdir(outfilename, 0777);
			*p = c;
		}
		out = Open(outfilename, MODE_NEWFILE);
		if (!out) {
			printf("can't write to: %s", outfilename);
			return 10;
		}
	}

	static uint8_t key[256] = {
			'o', 'p', 'e', 'n', 's', 's', 'h', '-', 'k', 'e', 'y', '-', 'v', '1', 0,
			0, 0, 0, 4, 'n', 'o', 'n', 'e',
			0, 0, 0, 4, 'n', 'o', 'n', 'e',
			0, 0, 0, 0,
			0, 0, 0, 1, // one key
			0, 0, 0, 0x33,
				0, 0, 0, 0xB, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', //copy
				0, 0, 0, 0x20,
	};
	uint8_t * t = key + 62;
	memcpy(t, pk, 32);
	t += 32;
	*(uint32_t *)t = 0x90; // TODO LEN
	t += 4;

	*(uint32_t *)t = 0; // TODO chksum
	t += 4;
	*(uint32_t *)t = 0; // TODO chksum
	t += 4;

	uint8_t * pubstart = t;
	memcpy(t, &key[62 - 4 - 0xb - 4], 0xb + 4 + 4); // copy
	t += 0xb + 4 + 4;

	memcpy(t, pk, 32);
	t += 32;
	uint8_t * pubend = t;

	*(uint32_t *)t = 0x40; // sk len
	t += 4;

	memcpy(t, sk, 64);
	t += 64;

	*(uint32_t *)t = 0x5; // Amiga len
	t += 4;
	memcpy(t, "Amiga", 5);
	t += 5;
	int pad = 0;
	while ((t - key - 2) & 15)
		*t++ = ++pad;

	static uint8_t mime[512];
	mimeEncode(mime, key, t - key);

	Write(out, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 36);

	for (uint8_t * p = mime, *q = p + strlen((char *)mime); p < q; p += 72) {
		int l = q - p;
		if (l > 72)
			l = 72;
		Write(out, p, l);
		Write(out, "\n", 1);
	}

	Write(out, "-----END OPENSSH PRIVATE KEY-----\n", 34);
	Close(out);

	// write pubs
	mimeEncode(mime, pubstart, pubend - pubstart);
	strcat(outfilename, ".pub");
	out = Open(outfilename, MODE_NEWFILE);
	if (!out) {
		printf("can't write %s", outfilename);
		return 5;
	}

	Write(out, "ssh-ed25519 ", 12);
	Write(out, mime, strlen((char *)mime));
	Write(out, " Amiga\n", 7);

	Close(out);

	return 0;
}

//char __stdiowin[128] = "CON://///AUTO/CLOSE/WAIT";
