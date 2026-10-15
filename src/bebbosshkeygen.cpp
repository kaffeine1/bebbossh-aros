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
extern "C" LONG bebbossh_aros_delete_file(const char *name);
#define BSSH_OPEN(name, mode) bebbossh_aros_open((name), (mode))
#define BSSH_CLOSE(file) bebbossh_aros_close((file))
#define BSSH_WRITE(file, buf, len) bebbossh_aros_write((file), (buf), (len))
#define BSSH_DELETE(name) bebbossh_aros_delete_file((name))
// the wrapper returns nothing; DOS Write() is unbuffered, so the Write()
// results already cover the data
#define BSSH_CLOSE_OK(file) (bebbossh_aros_close((file)), true)
#else
#define BSSH_OPEN(name, mode) Open((name), (mode))
#define BSSH_CLOSE(file) Close(file)
#define BSSH_WRITE(file, buf, len) Write((file), (buf), (len))
#define BSSH_DELETE(name) DeleteFile((name))
#define BSSH_CLOSE_OK(file) (Close(file) != 0)
#endif
#if BEBBOSSH_AROS && !defined(BEBBOSSH_AROS_MINCRT)
#define puts(s) Printf("%s\n", (s))
#define printf Printf
// Printf() output stays buffered until a newline: show the prompts
#define fflush(s) ((void)Flush(Output()))
#endif
#else
#include "amiemul.h"
#define BSSH_OPEN(name, mode) Open((name), (mode))
#define BSSH_CLOSE(file) Close(file)
#define BSSH_WRITE(file, buf, len) Write((file), (buf), (len))
#define BSSH_DELETE(name) DeleteFile((name))
// Close() is fclose() here, which returns 0 on success
#define BSSH_CLOSE_OK(file) (Close(file) == 0)
#endif
#if BEBBOSSH_AROS
#include <aros_randpool.h>
#endif


static char const *filename;
static char outfilename[256];

static char comment[256] = "Amiga";

#if defined(__AROS__) && defined(BEBBOSSH_TRACE_KEYGEN)
#define KGMAINTRACE(s) puts(s)
#else
#define KGMAINTRACE(s) ((void)0)
#endif

// write checks and secret wipes from patch 0008 of bebbossh 1.46.1 by
// Matthias Muench; volatile, so the compiler keeps the stores
static void wipe(void *p, unsigned len) {
	volatile uint8_t *v = (volatile uint8_t *) p;
	while (len--)
		*v++ = 0;
}

static bool writeAll(BPTR file, const void *p, int len) {
	return (int) BSSH_WRITE(file, p, len) == len;
}

#if BEBBOSSH_AROS && !defined(BEBBOSSH_AROS_MINCRT)
// RunCommand() puts the argument line into the Input() buffer: main() drops
// it with Flush() at a console, and redirected input is read with Read(),
// which bypasses that buffer (patch 0008 of bebbossh 1.46.1)
static bool consoleInput;
#endif

static char *readLine(char *buf, int len) {
#if BEBBOSSH_AROS && !defined(BEBBOSSH_AROS_MINCRT)
	if (!consoleInput) {
		int n = 0;
		char c;
		while (n < len - 1 && Read(Input(), &c, 1) == 1 && c != '\n')
			if (c != '\r')
				buf[n++] = c;
		buf[n] = 0;
		return buf;
	}
#endif
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
				// room for the ".pub" that is appended later (patch 0005 of
				// bebbossh 1.46.1 by Matthias Muench)
				if (strlen(argv[++i]) >= sizeof(outfilename) - 4) {
					printf("file name too long: %s\n", argv[i]);
					exit(10);
				}
				strcpy(outfilename, argv[i]);
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

	if (strlen(filename) >= sizeof(outfilename) - 4) {
		printf("file name too long: %s\n", filename);
		return 10;
	}
	strcpy(outfilename, filename);

	int paramStatus = parseParams(argc, argv);
	if (paramStatus)
		return paramStatus == 1 ? 0 : paramStatus;

#if defined(__AMIGA__) && !BEBBOSSH_AROS
	// remove the program arguments from stdin
	FGetC(stdin);
	fflush(stdin);
#elif BEBBOSSH_AROS && !defined(BEBBOSSH_AROS_MINCRT)
	consoleInput = IsInteractive(Input()) != 0;
	if (consoleInput)
		Flush(Input());
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
			if (strlen(buf) >= sizeof(outfilename) - 4) {
				printf("file name too long: %s\n", buf);
				return 10;
			}
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

#if BEBBOSSH_AROS && BEBBOSSH_RANDPOOL
	// a long-term key: more timer wake-ups and jitter on top of the pool's
	// first-use collection
	aros_randpool_stir(32);
	if (!(aros_randpool_flags() & AROS_RANDPOOL_JITTER_OK))
		puts("warning: little CPU timer jitter (emulated CPU?), see Random Numbers in README.AROS.txt");
	if (!(aros_randpool_flags() & AROS_RANDPOOL_SEED_SAVED))
		puts("note: the random seed ENVARC:.ssh/random_seed was not saved");
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
	wipe(az, sizeof(az));
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
			printf("can't write to: %s\n", outfilename);
			wipe(sk, sizeof(sk));
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
	// base64 of the private key blob: up to about 500 bytes with a 255
	// character comment, plus line breaks; 512 overflowed from ~150 characters
	static uint8_t mime[1024];
	mimeEncode(mime, key, t - key);

	bool ok = writeAll(out, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 36);

	for (uint8_t *p = mime, *q = p + strlen((char*) mime); ok && p < q; p += 72) {
		int l = q - p;
		if (l > 72)
			l = 72;
		ok = writeAll(out, p, l) && writeAll(out, "\n", 1);
	}

	ok = ok && writeAll(out, "-----END OPENSSH PRIVATE KEY-----\n", 34);
	ok = BSSH_CLOSE_OK(out) && ok;
	wipe(sk, sizeof(sk));
	// the first 62 bytes are the fixed header template; keep it for a resident rerun
	wipe(key + 62, sizeof(key) - 62);
	wipe(mime, sizeof(mime));
	if (!ok) {
		BSSH_DELETE(outfilename);
		printf("error writing %s\n", outfilename);
		return 10;
	}

	/* write public key */
	uint8_t pubbuf[4 + 11 + 4 + 32];
	uint8_t *pp = pubbuf;

	putAny(pp, "ssh-ed25519", 11);
	putAny(pp, pk, 32);

	mimeEncode(mime, pubbuf, pp - pubbuf);

	strcat(outfilename, ".pub");
	out = BSSH_OPEN(outfilename, MODE_NEWFILE);
	if (!out) {
		printf("can't write %s\n", outfilename);
		return 5;
	}

	ok = writeAll(out, "ssh-ed25519 ", 12)
			&& writeAll(out, mime, strlen((char* )mime))
			&& writeAll(out, " ", 1)
			&& writeAll(out, comment, strlen(comment))
			&& writeAll(out, "\n", 1);
	ok = BSSH_CLOSE_OK(out) && ok;
	if (!ok) {
		BSSH_DELETE(outfilename);
		printf("error writing %s\n", outfilename);
		return 5;
	}

	return 0;
}
