/*
 * bebbossh - Ed25519 key loader
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
 * Purpose: Load and validate Ed25519 private/public key pairs from OpenSSH key files
 *
 * Features:
 *  - Parse OpenSSH private key format (openssh-key-v1)
 *  - Base64 decode PEM sections
 *  - Extract and verify Ed25519 public/private key material
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with AllocVec/FreeVec memory management.
 *
 * Author's intent:
 *  Provide a reliable, GPL-compliant routine for loading Ed25519 keys
 *  into bebbossh client/server components.
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "mime.h"
#include "platform.h"
#include "ssh.h"

#if defined(__AMIGA__) || defined(__AROS__)
#include <proto/dos.h>
#include <proto/exec.h>
#include <amistdio.h>
#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT)
extern "C" BPTR bebbossh_aros_open(const char *name, LONG mode);
extern "C" void bebbossh_aros_close(BPTR file);
extern "C" LONG bebbossh_aros_read(BPTR file, void *buf, LONG len);
extern "C" LONG bebbossh_aros_seek(BPTR file, LONG offset, LONG mode);
extern "C" APTR bebbossh_aros_allocvec(IPTR byteSize, ULONG requirements);
extern "C" void bebbossh_aros_freevec(APTR memoryBlock);
#define BSSH_OPEN(name, mode) bebbossh_aros_open((name), (mode))
#define BSSH_CLOSE(file) bebbossh_aros_close((file))
#define BSSH_READ(file, buf, len) bebbossh_aros_read((file), (buf), (len))
#define BSSH_SEEK(file, offset, mode) bebbossh_aros_seek((file), (offset), (mode))
#define BSSH_ALLOCVEC(size, flags) bebbossh_aros_allocvec((size), (flags))
#define BSSH_FREEVEC(ptr) bebbossh_aros_freevec((ptr))
#else
#define BSSH_OPEN(name, mode) Open((name), (mode))
#define BSSH_CLOSE(file) Close((file))
#define BSSH_READ(file, buf, len) Read((file), (buf), (len))
#define BSSH_SEEK(file, offset, mode) Seek((file), (offset), (mode))
#define BSSH_ALLOCVEC(size, flags) AllocVec((size), (flags))
#define BSSH_FREEVEC(ptr) FreeVec((ptr))
#endif
#else
#include <stdio.h>
#include "amiemul.h"
#define BSSH_OPEN(name, mode) Open((name), (mode))
#define BSSH_CLOSE(file) Close((file))
#define BSSH_READ(file, buf, len) Read((file), (buf), (len))
#define BSSH_SEEK(file, offset, mode) Seek((file), (offset), (mode))
#define BSSH_ALLOCVEC(size, flags) AllocVec((size), (flags))
#define BSSH_FREEVEC(ptr) FreeVec((ptr))
#endif

#ifdef __AMIGA__
__attribute((section(".text")))
#endif
const static uint8_t KEYSTART[47] {
		0, 0, 0, 4, 'n', 'o', 'n', 'e',
		0, 0, 0, 4, 'n', 'o', 'n', 'e',
		0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0x33, 0, 0, 0, 0xB,
		's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9',
		0, 0, 0, 0x20,
};

extern char const * sshDir;
extern char const * keyFile;

bool loadEd25519Key(uint8_t * pk, uint8_t * sk, char const * keyfilename) {
	if (!keyFile) keyFile = concat(sshDir, ".ssh/id_ed25519", NULL);
	if (!keyfilename) keyfilename = keyFile;

	BPTR kfile = BSSH_OPEN(keyfilename, MODE_OLDFILE);
	if (!kfile) {
		if (strcmp(keyfilename, keyFile))
			logme(L_ERROR, "can't open `%s` for reading", keyfilename);
		return false;
	}
	logme(L_DEBUG, "loading key file `%s`", keyfilename);

	BSSH_SEEK(kfile, 0, OFFSET_END);
	int size = BSSH_SEEK(kfile, 0, OFFSET_BEGINNING);
	char * keymime = (char *)BSSH_ALLOCVEC(size + 1, MEMF_PUBLIC);
	uint8_t * keydata = (uint8_t *)BSSH_ALLOCVEC(size, MEMF_PUBLIC);

	bool r = true;
	if (keydata && keymime) {
		for (int read = 0; read < size;) {
			int in = BSSH_READ(kfile, keymime + read, size - read);
			if (in <= 0) {
				r = false;
				break;
			}
			read += in;
		}
		keymime[size] = 0;

		char * begin = r ? strstr(keymime, "-----BEGIN") : 0;
		char * end = strstr(keymime, "-----END");
		char * data = 0;
		if (begin)
			data = strstr(begin + 10, "-----");
		if (data && end) {
			data += 5;
			*end = 0;
			logme(L_FINE, "base64: %s", data);

			mimeDecode(keydata, (uint8_t *)data, end - data);

			if (strcmp((char *)keydata, "openssh-key-v1") ||
					memcmp(keydata + 15, KEYSTART, sizeof(KEYSTART))) {
				r = false;
			} else {
				uint8_t * p = keydata + 15 + sizeof(KEYSTART);
				memcpy(pk, p, 32);
				p += 32 + 12; // skip length and checksum
				if (memcmp(&KEYSTART[28], p, 19)) {
					r = false;
				} else {
					p += 19; // skip length and ssh-ed25519
					if (memcmp(p, pk, 32)) { // same PK
						r = false;
					} else {
						p += 32;
						static uint8_t SKLEN[4] = {0, 0, 0, 0x40};
						if (memcmp(p, SKLEN, 4)) {
							r = false;
						} else {
							memcpy(sk, p + 4, 0x40);
						}
					}
				}
			}
			if (!r) {
				logme(L_ERROR, "can't handle this key file");
			}
		} else {
			r = false;
			logme(L_ERROR, "not a valid key file");
		}
		memset(keydata, 0, size);
		memset(keymime, 0, size);
		BSSH_FREEVEC(keydata);
		BSSH_FREEVEC(keymime);
	} else {
		r = false;
		logme(L_ERROR, "no mem for %ld bytes", size);
	}
	BSSH_CLOSE(kfile);
	return r;
}
