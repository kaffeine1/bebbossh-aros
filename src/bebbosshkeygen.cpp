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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <ed25519.h>
#include <mime.h>
#include <platform.h>
#include <rand.h>
#include <test.h>
#include <ssh.h>
#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT)
#include <ed25519i.h>
#endif
#include "revision.h"

#if BEBBOSSH_AMIGA_API
#include <amistdio.h>
#include <proto/dos.h>
#include <proto/exec.h>
#if defined(BEBBOSSH_AROS_MINCRT)
extern "C" BPTR bebbossh_aros_open(const char *name, LONG mode);
extern "C" void bebbossh_aros_close(BPTR file);
extern "C" LONG bebbossh_aros_write(BPTR file, const void *buf, LONG len);
#define BSSH_OPEN(name, mode) bebbossh_aros_open((name), (mode))
#define BSSH_CLOSE(file) bebbossh_aros_close((file))
#define BSSH_WRITE(file, buf, len) bebbossh_aros_write((file), (buf), (len))
#else
#define BSSH_OPEN(name, mode) Open((name), (mode))
#define BSSH_CLOSE(file) Close(file)
#define BSSH_WRITE(file, buf, len) Write((file), (buf), (len))
#endif
#if BEBBOSSH_AROS && !defined(BEBBOSSH_AROS_MINCRT)
#define puts(s) Printf("%s\n", (s))
#define printf Printf
#define fflush(s) ((void)0)
#endif
#else
#include "amiemul.h"
#define BSSH_OPEN(name, mode) Open((name), (mode))
#define BSSH_CLOSE(file) Close(file)
#define BSSH_WRITE(file, buf, len) Write((file), (buf), (len))
#endif


static char const *filename;
static char outfilename[256];

static char comment[256] = "Amiga";

#if defined(__AROS__) && defined(BEBBOSSH_TRACE_KEYGEN)
#define KGMAINTRACE(s) puts(s)
#else
#define KGMAINTRACE(s) ((void)0)
#endif

static char *readLine(char *buf, int len) {
#if BEBBOSSH_AMIGA_API
	char *s = FGets(Input(), buf, len);
#else
	char *s = fgets(buf, len, stdin);
#endif
	if (!s)
		return s;
	char *p = strpbrk(buf, "\r\n");
	if (p)
		*p = 0;
	return s;
}

static void printUsage() {
    puts(__VERSION__);
    puts("USAGE: amigasshkeygen [-f <output_keyfile>] [-C <comment>]");
    puts("    -f <file>    specify output key filename");
    puts("    -C <comment> set key comment (default: \"Amiga\")");
    puts("    -?           display this help");
}

static int parseParams(unsigned argc, char **argv) {
	char *arg = 0;
	int normal = 0;

	for (unsigned i = 1; i < argc; ++i) {
		arg = argv[i];
		if (arg[0] == '-') {
			switch (arg[1]) {
			case '?':
				goto usage;
			case 'f':
			case 'F':
				if (arg[2])
					goto invalid;

				if (i + 1 == argc)
					goto missing;
				strcpy(outfilename, argv[++i]);
				continue;
			case 'c':
			case 'C':
			    if (arg[2])
			        goto invalid;
			    if (i + 1 == argc)
			        goto missing;
			    strncpy(comment, argv[++i], 255);
			    comment[255] = 0;
			    continue;
			default:
				goto invalid;
			}
		}
		++normal;
	}
	if (normal)
		puts("ignoring additional arguments");
	return 0;

	usage: printUsage();
	return 1;

	missing: printf("missing parameter for %s\r\n", arg);
	return 10;

	invalid: printf("invalid option %s\r\n", arg);
	return 10;
}

extern char const * sshDir;

__stdargs int main(int argc, char **argv) {
	static char buf[256];

#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT)
	filename = "HOSTKEY";
#else
	filename = concat(sshDir, ".ssh/id_ed25519", NULL);
#endif

	strcpy(outfilename, filename);

	int paramStatus = parseParams(argc, argv);
	if (paramStatus)
		return paramStatus == 1 ? 0 : paramStatus;

#if defined(__AMIGA__) && !BEBBOSSH_AROS
	// remove the program arguments from stdin
	FGetC(stdin);
	fflush(stdin);
#endif

	puts("Generating public/private ed25519 key pair");

#if !(defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT))
	if (0 == strcmp(outfilename, filename)) {
		printf("Enter file in which to save the key (%s): ", outfilename);
		fflush(stdout);
		readLine(buf, 255);
		if (*buf > 32) {
			char *p = buf;
			for (; *p > ' '; ++p)
				;
			*p = 0;
			strcpy(outfilename, buf);
		}
	}
#endif

#if !(defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT))
	BPTR xist = BSSH_OPEN(outfilename, MODE_OLDFILE);
	if (xist) {
		BSSH_CLOSE(xist);
		printf("%s already exists.\nOverwrite (y/n)? ", outfilename);
		static char buf2[4];
		fflush(stdout);
		readLine(buf2, 3);
		if (*buf2 != 'y' && *buf2 != 'Y')
				return 0;
	}
#endif

	static uint8_t pk[32];
	static uint8_t sk[64];
#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT)
	static uint8_t az[64];
	KGMAINTRACE("keygen: before randfill");
	randfill(sk, 32);
	KGMAINTRACE("keygen: after randfill");
	secret_expand(az, sk);
	KGMAINTRACE("keygen: after secret_expand");
	ge_pubkey(pk, az);
	KGMAINTRACE("keygen: after ge_pubkey");
	memcpy(sk + 32, pk, 32);
#else
	ge_new_keypair_ed25519(pk, sk);
#endif

	static char gfx[9][21];
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

	BPTR out = BSSH_OPEN(outfilename, MODE_NEWFILE);
	if (!out) {
		char *p = outfilename + strlen(outfilename);
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
		out = BSSH_OPEN(outfilename, MODE_NEWFILE);
		if (!out) {
			printf("can't write to: %s", outfilename);
			return 10;
		}
	}

	/* Build OpenSSH private key blob */
	static uint8_t key[512] = {
			'o', 'p', 'e', 'n', 's', 's', 'h', '-', 'k', 'e', 'y', '-', 'v', '1', 0,
			0, 0, 0, 4, 'n', 'o', 'n', 'e', /* ciphername */
			0, 0, 0, 4, 'n', 'o', 'n', 'e', /* kdfname */
			0, 0, 0, 0, /* kdfoptions (empty) */
			0, 0, 0, 1, /* number of keys */
			0, 0, 0, 0x33, /* public key length (51) */
			0, 0, 0, 0x0b, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9',
			0, 0, 0, 0x20 /* pubkey length (32), data follows at runtime */
	};

	/* Fill public key in the header */
	uint8_t *t = key + 62; /* 15 + 4 + 4 + 4 + 4 + 4 + 11 + 4 = 62 */
	memcpy(t, pk, 32);
	t += 32;

	/* Reserve space for private block length */
	uint8_t *privLenPos = t;
	t += 4;

	uint8_t *privStart = t;

	/* Checksums (must be identical, non-zero) */
	uint32_t cksum;
	randfill(&cksum, 4);
	putInt32AndInc(t, cksum);
	putInt32AndInc(t, cksum);

	/* key type string */
	putAny(t, "ssh-ed25519", 11);

	/* public key string */
	putAny(t, pk, 32);

	/* private key string: length + 64 bytes sk */
	putInt32AndInc(t, 64);
	memcpy(t, sk, 64);
	t += 64;

	/* comment string */
	putAny(t, comment, strlen(comment));

	/* padding to 8-byte alignment */
	uint8_t pad = 1;
	while (((t - privStart) % 8) != 0)
		*t++ = pad++;

	/* write private block length */
	uint32_t privLen = (uint32_t) (t - privStart);
	putInt32Aligned(privLenPos, privLen);

	/* MIME-encode private key */
	static uint8_t mime[512];
	mimeEncode(mime, key, t - key);

	BSSH_WRITE(out, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 36);

	for (uint8_t *p = mime, *q = p + strlen((char*) mime); p < q; p += 72) {
		int l = q - p;
		if (l > 72)
			l = 72;
		BSSH_WRITE(out, p, l);
		BSSH_WRITE(out, "\n", 1);
	}

	BSSH_WRITE(out, "-----END OPENSSH PRIVATE KEY-----\n", 34);
	BSSH_CLOSE(out);

	/* write public key */
	uint8_t pubbuf[4 + 11 + 4 + 32];
	uint8_t *pp = pubbuf;

	putAny(pp, "ssh-ed25519", 11);
	putAny(pp, pk, 32);

	mimeEncode(mime, pubbuf, pp - pubbuf);

	strcat(outfilename, ".pub");
	out = BSSH_OPEN(outfilename, MODE_NEWFILE);
	if (!out) {
		printf("can't write %s", outfilename);
		return 5;
	}

	BSSH_WRITE(out, "ssh-ed25519 ", 12);
	BSSH_WRITE(out, mime, strlen((char* )mime));
	BSSH_WRITE(out, " ", 1);
	BSSH_WRITE(out, comment, strlen(comment));
	BSSH_WRITE(out, "\n", 1);

	BSSH_CLOSE(out);

	return 0;
}
