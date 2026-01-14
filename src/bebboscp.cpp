/*
 * bebboscp - secure copy (SCP) client
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
 * Project: bebbossh - SCP client for Amiga
 * Purpose: Provide secure file transfer capabilities over SSH2/SFTP
 *
 * Features:
 *  - Local and remote file copy with attribute preservation
 *  - Directory traversal and pattern matching
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with bsdsocket.library integration.
 *
 * Author's intent:
 *  Enable Amiga developers to securely copy files between systems
 *  using modern SSH protocols.
 * ----------------------------------------------------------------------
 */
#include <stdint.h>

#include <stdlib.h>
#include <fnmatch.h>

#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>

#ifdef __AMIGA__
#include <amistdio.h>
#include <dos/dostags.h>
#include <exec/execbase.h>
#include <intuition/intuitionbase.h>
#include <intuition/intuition.h>
#include <workbench/startup.h>

#include <clib/alib_protos.h>
#include <proto/dos.h>
#include <proto/exec.h>
#include <proto/icon.h>
#include <proto/intuition.h>
#include <proto/socket.h>

#include <stabs.h>

#include "keyboard.h"

typedef BPTR DPTR;
#define IS_FILE(fib) ((fib).fib_DirEntryType <= 0)
#define IS_DIR(fib) ((fib).fib_DirEntryType > 0)
#define IS_LINK(fib) ((fib).fib_DirEntryType == 3)

typedef BPTR FPTR;
#define ExamineF(l,f) Examine(l,f)
#define LockF(f,m) Lock(f,m)
#define UnLockF(f) UnLock(f)

#define DateStampF DateStamp
static inline long delta_ms(const struct DateStamp &now,
                            const struct DateStamp &then) {
    /* convert both to total ticks since epoch */
    long ticks_now  = now.ds_Tick
                    + now.ds_Minute * 50
                    + now.ds_Days * 24 * 60 * 50;
    long ticks_then = then.ds_Tick
                    + then.ds_Minute * 50
                    + then.ds_Days * 24 * 60 * 50;

    long diff_ticks = ticks_now - ticks_then;

    /* each tick = 20 ms */
    return diff_ticks * 20;
}

#else
#include "amiemul.h"
#endif

#include "log.h"
#include "stack.h"

#include "revision.h"
#include "ssh.h"
#include "sftp.h"
#include "test.h"
#include "client.h"
#include "clientchannel.h"

extern char const * sshDir;

static bool pty = false;

static char *src;
static char *dst;

static void erase();
static void printStats(bool);

extern char portSet, usernameSet, keyfileSet, loglevelSet;
extern char const * configFile;
extern char const * encOrder;
extern char const * userOrder;

static uint8_t CHANNEL_PTY[17] = {
SSH_MSG_CHANNEL_REQUEST, 0x00, 0x00, 0x00, 0x00, // channel 0
		0x00, 0x00, 0x00, 0x07, 'p', 't', 'y', '-', 'r', 'e', 'q', 0x01, // want reply
		};
#ifdef __AMIGA__
static const char *TERM = "xterm-amiga";
#else
static const char *TERM = "xterm";
#endif
extern uint32_t numCols;
extern uint32_t numRows;
static uint8_t TERMCAPS[43] = { 0x00, 0x00, 0x00, 0x0, // terminal width, pixels
		0x00, 0x00, 0x00, 0x0, // terminal height, pixels
		0x00, 0x00, 0x00, 6 * 5 + 1, // length of the options
		0x01, 0x00, 0x00, 0x00, 'C' - 'A' + 1, // VINTR -> CTRL+C - does it work?
		0x03, 0x00, 0x00, 0x00, 0x08, // VERASE -> Backspace
		0x05, 0x00, 0x00, 0x00, 'D' - 'A' + 1, // VEOF
		0x08, 0x00, 0x00, 0x00, 'Q' - 'A' + 1, 0x09, 0x00, 0x00, 0x00, 'S' - 'A' + 1, 0x3B, 0x00, 0x00, 0x00, 0x01, // IEXTEN
		0x00 // end of options
		};

static char const * lastPart(char const * s) {
	char const * sc = s;
	while (*s) {
		if (*s == ':' || *s == '/')
			sc = s + 1;
		++s;
	}
	return sc;
}

static bool sendNewPty() {
	uint8_t *p = buffer + 5;
	memcpy(p, CHANNEL_PTY, sizeof(CHANNEL_PTY));
	p += sizeof(CHANNEL_PTY);

	putString(p, TERM);

	putInt32AndInc(p, numCols);
	putInt32AndInc(p, numRows);

	memcpy(p, TERMCAPS, sizeof(TERMCAPS));
	int len = p - (buffer + 5) + sizeof(TERMCAPS);

	return sendEncrypted(buffer + 5, len);
}

bool getConsoleSize();

enum estate {
	STATE_NONE, STATE_INIT,
	STATE_REALPATH, STATE_STAT,
	STATE_DST_OPEN, STATE_DST_WRITE, STATE_DST_CLOSE,
	STATE_DST_MKDIR, STATE_STAT_DSTDIR,
	STATE_SRC_OPEN, STATE_SRC_READ, STATE_SRC_CLOSE,
	STATE_SRC_OPENDIR, STATE_SRC_READDIR, STATE_SRC_CLOSEDIR,
	STATE_ERROR,
};

struct CopyState {
	struct FileInfoBlock fib;
	bool srcIsDir;
	char *src;
	char *dst;
	char *pattern;
	char *outname;

	// local file
	uint32_t pos;
	BPTR localFile;

	// local dir
	DPTR localDir;

	// remote dir
	Stack<CopyState> * entries;

	// remote infos
	uint32_t flags;
	uint32_t sizeHi;
	uint32_t size;
	uint32_t protect;
	struct DateStamp date;

	// remote file/dir handle
	uint32_t handleSize;
	void * handle;

	private:
	CopyState(){} // @suppress("Class members should be properly initialized")
	public:
	static CopyState dummy;

	CopyState(bool srcIsDir_, char *src_, char *dst_, char *pattern_, char *outname_) {
		srcIsDir = srcIsDir_;
		src = strdup(src_);
		dst = strdup(dst_);
		pattern = pattern_;
		outname = outname_;

		logme(L_DEBUG, "src=%s -> dst=%s", src, dst);

		pos = 0;
		localFile = 0;
		localDir = 0;
		entries = 0;
		flags = 0;
		sizeHi = 0;
		size = 0;
		protect = 0;
#ifdef __AMIGA__
		date = {0, 0, 0};
#else
		date = {0, 0};
#endif
		handleSize = 0;
		handle = 0;
	}

	void freeEntries() {
		if (entries) {
			for (uint32_t i = 0; i < entries->getMax(); ++i) {
				CopyState * cs = (*entries)[i];
				delete cs;
			}
			delete entries;
			entries = 0;
		}
	}


	~CopyState() {
		freeEntries();
		if (localFile) {
			Close(localFile);
		}
		if (localDir) {
			UnLock(localDir);
		}
		free(src);
		free(dst);
		free(handle);
	}
	bool setAttrs(uint8_t * &p);
};

// dummy to eat attributes
CopyState CopyState::dummy;

// references the current file
static CopyState *currentCs;

bool CopyState::setAttrs(uint8_t * &p) {
	flags = getInt32(p);
	p += 4;

	if (flags & SSH_FILEXFER_ATTR_SIZE) { // 1
		sizeHi = getInt32(p);
		p += 4;
		size = getInt32(p);
		p += 4;
	}
	if (flags & SSH_FILEXFER_ATTR_ALLOCATION_SIZE)
		p += 8;
	if (flags & SSH2_FILEXFER_ATTR_UIDGID)
		p += 8;
	if (flags & SSH_FILEXFER_ATTR_OWNERGROUP) {
		uint32_t l = getInt32(p); // skip owner
		p += l + 4;
		l = getInt32(p);	// skip group
		p += l + 4;
	}

	uint32_t mode = 0;
	if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) { // 4
		mode = getInt32(p);
		p += 4;
#ifdef __AMIGA__
		protect = ssh2amode(mode);
#else
		protect = mode;
#endif
	}
	struct timeval tv;
	if (flags & SSH_FILEXFER_ATTR_CREATETIME) {
		tv.tv_sec = getInt32(p);
		p += 4;
		tv.tv_usec = getInt32(p);
		p += 4;
	}
	if (flags & SSH2_FILEXFER_ATTR_ACMODTIME) { // 8
		tv.tv_sec  = getInt32(p);
		p += 4;
		tv.tv_usec = getInt32(p);
		p += 4;
	}
	if (flags & (SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_CREATETIME | SSH2_FILEXFER_ATTR_ACMODTIME)) {
#ifdef __AMIGA__
		date.ds_Tick = tv.tv_usec / 20000 + (tv.tv_sec % 60) * 1000000;
		date.ds_Days = tv.tv_sec / (24 * 60 * 60);
		date.ds_Minute = (tv.tv_sec - date.ds_Days * (24 * 60 * 60)) / 60;
#else
		date.tv_sec  = tv.tv_sec;
		date.tv_nsec = tv.tv_usec * 1000;  // convert microseconds -> nanoseconds
#endif
	}

	return 040000 & mode;
}

Stack<CopyState> stack;

class ScpChannel: public ClientChannel {
	static uint32_t REQUESTID;

	bool pty;
	enum estate state;

	bool localSrc;
	bool srcIsDir;
	bool dstIsDir;
	char *src;
	char *dst;
	char *pattern;
	char *outname;

public:
	ScpChannel(bool pty_, bool localSrc_, char *src_, char *dst_);
	bool start();
	virtual int processChannelData(void *data, int len);

	void sendChannelData(uint8_t *p);

	void init();
	void getRealPath(char const *path);
	void getLStat(char const *path);

	void openFile(CopyState *cs, bool write);
	void readData(CopyState *cs);
	int writeData(CopyState *cs);
	void closeFile(CopyState *cs);

	void mkDir(CopyState * cs);
	void openDir(CopyState * cs);
	void readDir(CopyState * cs);

	void appendOutname();
};

static ScpChannel * theSCP;

uint32_t ScpChannel::REQUESTID;

ScpChannel::ScpChannel(bool pty_, bool localSrc_, char *src_, char *dst_) :
		ClientChannel(0), pty(pty_), state(STATE_NONE), localSrc(localSrc_),
		srcIsDir(true), dstIsDir(false), src(src_), dst(dst_), pattern(0), outname(0) {
	getConsoleSize();
}

void ScpChannel::sendChannelData(uint8_t *end) {
	uint8_t *p0 = buffer + 5;
	uint8_t *p = p0;
	*p++ = SSH_MSG_CHANNEL_DATA;
	putInt32AndInc(p, getChannelNo());

	putInt32AndInc(p, end - p - 4); // total length
	putInt32AndInc(p, end - p - 4); // inner length

//	_dump("send", p0, end - p0);
	sendEncrypted(p0, end - p0);
}

void ScpChannel::init() {
	maxBuffer = ::maxBuffer;

	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_INIT;
	putInt32AndInc(p, 3);
	logme(L_DEBUG, "SSH_FXP_INIT");
	sendChannelData(p);

	remoteChannelNo = 0;
}

void ScpChannel::getRealPath(char const *path) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_REALPATH;
	putInt32AndInc(p, ++REQUESTID);
	putString(p, path);
	logme(L_DEBUG, "%ld SSH_FXP_REALPATH %s",REQUESTID, path);
	sendChannelData(p);
}

void ScpChannel::getLStat(char const *path) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_LSTAT;
	putInt32AndInc(p, ++REQUESTID);
	putString(p, path);
	logme(L_DEBUG, "%ld SSH_FXP_LSTAT %s",REQUESTID, path);
	sendChannelData(p);
}

void ScpChannel::openFile(CopyState * cs, bool write) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_OPEN;
	putInt32AndInc(p, ++REQUESTID);

	putString(p, write ? cs->dst : cs->src);

	if (write) {
		putInt32AndInc(p, 0xa); // CREATE
		putInt32AndInc(p, SSH_FILEXFER_ATTR_PERMISSIONS);
		putInt32AndInc(p, a2sshmode(cs->protect));
	} else {
		putInt32AndInc(p, 1); // READ
		putInt32AndInc(p, 0);
	}

	logme(L_DEBUG, "%ld SSH_FXP_OPEN %s",REQUESTID, write ? cs->dst : cs->src);
	sendChannelData(p);
}


void ScpChannel::mkDir(CopyState * cs) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_MKDIR;
	putInt32AndInc(p, ++REQUESTID);
	putString(p, cs->dst);
	putInt32AndInc(p, SSH_FILEXFER_ATTR_PERMISSIONS);
	putInt32AndInc(p, a2sshmode(cs->protect));

	logme(L_DEBUG, "%ld SSH_FXP_MKDIR %s",REQUESTID, cs->dst);
	sendChannelData(p);
}

void ScpChannel::openDir(CopyState * cs) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_OPENDIR;
	putInt32AndInc(p, ++REQUESTID);
	putString(p, cs->src);

	logme(L_DEBUG, "%ld SSH_FXP_OPENDIR %s",REQUESTID, cs->src);
	sendChannelData(p);
}

void ScpChannel::readDir(CopyState * cs) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_READDIR;
	putInt32AndInc(p, ++REQUESTID);

	putInt32AndInc(p, cs->handleSize);
	memcpy(p, cs->handle, cs->handleSize);
	p += cs->handleSize;

	logme(L_DEBUG, "%ld SSH_FXP_READDIR %s",REQUESTID, cs->src);
	sendChannelData(p);}

void ScpChannel::readData(CopyState *cs) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_READ;
	putInt32AndInc(p, ++REQUESTID);

	putInt32AndInc(p, cs->handleSize);
	memcpy(p, cs->handle, cs->handleSize);
	p += cs->handleSize;
	putInt32AndInc(p, 0); // no support > 4G
	putInt32AndInc(p, cs->pos);
	putInt32AndInc(p, maxBuffer);

	logme(L_DEBUG, "%ld SSH_FXP_READ %s",REQUESTID, cs->src);
	sendChannelData(p);
}

int ScpChannel::writeData(CopyState *cs) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_WRITE;
	putInt32AndInc(p, ++REQUESTID);

	putInt32AndInc(p, cs->handleSize);
	memcpy(p, cs->handle, cs->handleSize);
	p += cs->handleSize;
	putInt32AndInc(p, 0); // no support > 4G
	putInt32AndInc(p, cs->pos);

	int read = Read(cs->localFile, p + 4, maxBuffer);
	logme(L_DEBUG, "remote writing %ld", read);
	if (read > 0) {
		cs->pos += read;
		putInt32AndInc(p, read);
		p += read;

		logme(L_DEBUG, "%ld SSH_FXP_WRITE %s",REQUESTID, cs->dst);
		sendChannelData(p);
	}
	return read;
}

void ScpChannel::closeFile(CopyState *cs) {
	uint8_t *p = buffer + 18;
	*p++ = SSH_FXP_CLOSE;
	putInt32AndInc(p, ++REQUESTID);

	putInt32AndInc(p, cs->handleSize);
	memcpy(p, cs->handle, cs->handleSize);
	p += cs->handleSize;

	logme(L_DEBUG, "%ld SSH_FXP_CLOSE %s",REQUESTID, cs->dst);
	sendChannelData(p);

	if (cs->localFile) {
		logme(L_FINE, "closing file %08lx", cs->localFile);
		Close(cs->localFile);
		cs->localFile = 0;
	}
	if (cs->localDir) {
		logme(L_FINE, "closing dir %08lx", cs->localDir);
		UnLock(cs->localDir);
		cs->localDir = 0;
	}
	free(cs->handle);
	cs->handleSize = 0;
	cs->handle = 0;
}

static char * concatPath(char * a, char * b) {
	char * q = a;
	while (*q) {
		++q;
	}
	if (q[-1] == ':')
		return concat(a, b, 0);
	return concat(a, "/", b, 0);
}

void ScpChannel::appendOutname() {
	if (!currentCs->outname || !*currentCs->outname)
		return;

	char * q = concatPath(currentCs->dst, currentCs->outname);
	free(currentCs->outname);
	currentCs->outname = 0;
	free(currentCs->dst);
	currentCs->dst = q;
}

int ScpChannel::processChannelData(void *data, int length) {
	static int pendingRead;

	if (stack.getCount() == 0)
		currentCs = 0;
	else
		currentCs = stack.peek();

	if (pendingRead > 0) {
		if (!currentCs)
			return -1;

		int read = length > pendingRead ? pendingRead : length;
		logme(L_DEBUG, "pending read %ld %ld", read);

		if (Write(currentCs->localFile, data, read) != read) {
			logme(L_ERROR, "write failed for `%s`", currentCs->dst);
			return -1;
		}
		currentCs->pos += read;

		pendingRead -= read;
		if (pendingRead <= 0)
			readData(currentCs);
		return 0;
	}

	uint8_t *p = (uint8_t*) data;

	logme(L_DEBUG, "state=%ld", state);
//	_dump("recv", p, length > 128 ? 128 : length);
	uint32_t sz = getInt32(p);
	p += 4;

	uint8_t k = *p++;

	if (k > SSH_FXP_VERSION) {
		uint32_t requestId = getInt32(p);
		p += 4;
		if (requestId != REQUESTID) {
			logme(L_ERROR, "invalid requestId %ld <> %ld", requestId, REQUESTID);
			return -1;
		}
	}

	// where is currentCs needed?
	switch (state) {
	case STATE_DST_OPEN:
	case STATE_DST_WRITE:
	case STATE_DST_CLOSE:
	case STATE_DST_MKDIR:
	case STATE_STAT_DSTDIR:
	case STATE_SRC_OPEN:
	case STATE_SRC_READ:
	case STATE_SRC_CLOSE:
	case STATE_SRC_OPENDIR:
	case STATE_SRC_READDIR:
	case STATE_SRC_CLOSEDIR:
		if (!currentCs)
			return -1;
	}

	switch (state) {
	case STATE_INIT: {
		if (k != SSH_FXP_VERSION) {
			logme(L_ERROR, "expected SSH_FXP_VERSION=2, got %ld", k);
			return -1;
		}
		if (localSrc) {
			getRealPath(dst);
		} else {
			getRealPath(src);
		}
		state = STATE_REALPATH;
		return 0; // OK
	}
	case STATE_REALPATH: {
		if (k != SSH_FXP_NAME) {
			logme(L_ERROR, "could not resolve %s", localSrc ? dst : src);
			return -1;
		}
		uint32_t count = getInt32(p);
		p += 4;
		if (count > 0) {
			uint8_t *name = sshString(p);
			if (p < buffer || p - length > data)
				return -1; // string too long
			if (localSrc)
				dst = strdup((char*) name); // use the real path
			else
				src = strdup((char*) name); // use the real path
		}

		state = STATE_STAT;
		getLStat(localSrc ? dst : src);
		return 0;
	}
	case STATE_STAT: {
		if (k == SSH_FXP_STATUS) {
			// stat failed
			if (outname || !localSrc) { // outname exists
				logme(L_ERROR, "object not found: %s", localSrc ? dst : src);
				return -1;
			}
			// split dst into parent / outname
			char *slashColon = 0;
			char *star = 0;
			char *q = dst;
			while (*q) {
				if (*q == ':' || *q == '/')
					slashColon = q;
				++q;
			}
			if (slashColon) {
				outname = strdup(slashColon + 1);
				if (*slashColon == ':')
					++slashColon;
				*slashColon = 0;
			}
			getLStat(dst);
			return 0;
		}
		if (k != SSH_FXP_ATTRS) {
			logme(L_ERROR, "expected SSH_FXP_ATTRS=105, got %ld", k);
			return -1;
		}

		// setup copy state local to remote
		currentCs = new CopyState(srcIsDir, src, dst, pattern, outname);
		if (!currentCs)
			return -1;

		stack.add(stack.getCount(), currentCs);

		// create dst name
		if (!currentCs->outname) {
			// grab last part from src
			currentCs->outname = strdup(lastPart(src));
		}

		if (!localSrc) {
			currentCs->srcIsDir = currentCs->setAttrs(p);

OpenRemoteDirOrFile:
			if (currentCs->srcIsDir) {
				DPTR dirLock = Lock(currentCs->dst, SHARED_LOCK);
				if (!dirLock)
					dirLock = CreateDir(currentCs->dst);
				if (!dirLock) {
					logme(L_ERROR, "can't create dir `%s`", currentCs->dst);
					return -1;
				}
				Examine(dirLock, &currentCs->fib);
				UnLock(dirLock);

				if (IS_FILE(currentCs->fib)) {
					logme(L_ERROR, "not a dir `%s`", currentCs->dst);
					return -1;
				}

				SetProtection(currentCs->dst, currentCs->protect);

				state = STATE_SRC_OPENDIR;
				openDir(currentCs);
				return 0;
			}

			DPTR dirLock = Lock(currentCs->dst, SHARED_LOCK);
			if (dirLock) {
				Examine(dirLock, &currentCs->fib);
				UnLock(dirLock);

				if (!IS_FILE(currentCs->fib) && 0 == strcmp(currentCs->dst, dst)) {
					if (outname == 0)
						outname = (char *)lastPart(src);
					appendOutname();
				}
			}


			BPTR file = Open(currentCs->dst, MODE_NEWFILE);
			if (!file) {
				logme(L_ERROR, "can't open file `%s` for writing", currentCs->dst);
				return -1;
			}

			currentCs->localFile = file;

			state = STATE_SRC_OPEN;
			openFile(currentCs, false);

			return 0;
		}

OpenLocalDirOrFile:
		appendOutname();

		if (currentCs->srcIsDir) {
			// it's a dir
			currentCs->localDir = Lock(currentCs->src, SHARED_LOCK);
			if (!currentCs->localDir || !Examine(currentCs->localDir, &currentCs->fib)) {
				logme(L_ERROR, "can't access dir `%s`", currentCs->src);
				return -1;
			}

#ifdef __AMIGA__
			// don't create volumes
			if (currentCs->dst[strlen(currentCs->dst) - 1] == ':')
				goto ExamineNext;
#endif

			state = STATE_DST_MKDIR;
			mkDir(currentCs);
		} else {
			// it's a file!
			FPTR lock = LockF(currentCs->src, SHARED_LOCK);
			currentCs->localFile = Open(currentCs->src, MODE_OLDFILE);
			if (!currentCs->localFile || !lock) {
				if (lock)
					UnLockF(lock);
				if (currentCs->localFile) {
					Close(currentCs->localFile);
					currentCs->localFile = 0;
				}
				logme(L_ERROR, "can't open `%s` for reading", currentCs->src);
				return -1;
			}
			ExamineF(lock, &currentCs->fib);
			currentCs->protect = currentCs->fib.fib_Protection;
			currentCs->size = currentCs->fib.fib_Size;
			UnLockF(lock);

			state = STATE_DST_OPEN;
			openFile(currentCs, true);
		}
		return 0;
	}
	case STATE_SRC_OPEN:
		if (k != SSH_FXP_HANDLE) {
			logme(L_ERROR, "can't open remote `%s` for reading", currentCs->src);
			return -1;
		}
		// copy the handle
		currentCs->handleSize = getInt32(p); p += 4;

		if (p + currentCs->handleSize - length > data)
			return -1;

		currentCs->handle = malloc(currentCs->handleSize);
		memcpy(currentCs->handle, p, currentCs->handleSize);

		currentCs->pos = 0;
		state = STATE_SRC_READ;
		readData(currentCs);
		return 0;

	case STATE_SRC_READ:
		if (k != SSH_FXP_DATA) {
			uint32_t reason = getInt32(p);
			if (reason != SSH_FX_EOF)
			{
				logme(L_ERROR, "read failed for remote `%s`: %ld", currentCs->src, reason);
				return -1;
			}
			putInt32AndInc(p, 0);
			p -= 4;
		}
		{
			uint32_t len = getInt32(p);
			if (len == 0) {
				closeFile(currentCs);
				state = STATE_SRC_CLOSE;
				return 0;
			}

			p += 4;

			// handle partial data
			int avail = length - (p - (uint8_t*)data);
			pendingRead = 0;
			if (avail < len) {
				pendingRead = len - avail;
				logme(L_DEBUG, "avail %ld data, want %ld -> pending %ld", avail, len, pendingRead);
				len = avail;				
			}

			if (Write(currentCs->localFile, p, len) != len) {
				logme(L_ERROR, "write failed for `%s`", currentCs->dst);
				return -1;
			}
			currentCs->pos += len;

			if (pendingRead <= 0)
				readData(currentCs);
		}
		return 0;
	case STATE_SRC_CLOSE:
		erase();
		printStats(true);

		if (k != SSH_FXP_STATUS) {
			logme(L_ERROR, "closing remote `%s` failed: %ld", currentCs->src, getInt32(p));
			return -1;
		}
		/* no break */
	case STATE_SRC_CLOSEDIR:
		stack.pop();
		delete currentCs;
		if (stack.getCount()) {
			currentCs = stack.peek();
			if (currentCs->srcIsDir) {
				goto HandleNext;
			}
			logme(L_ERROR, "can't happen!? but srcIsDir flag is not set");
		}
		stopped = 1;
		return 0;
	case STATE_DST_OPEN:
//		logme(L_ERROR, "STATE_DST_OPEN");
		if (k != SSH_FXP_HANDLE) {
			logme(L_ERROR, "can't open `%s` for writing", currentCs->dst);
			return -1;
		}

		// copy the handle
		currentCs->handleSize = getInt32(p); p += 4;
		if (p + currentCs->handleSize - length > data)
			return -1;

		currentCs->handle = malloc(currentCs->handleSize);
		memcpy(currentCs->handle, p, currentCs->handleSize);

		currentCs->pos = 0;
		state = STATE_DST_WRITE;

		/* no break */
	case STATE_DST_WRITE:
//		logme(L_ERROR, "STATE_DST_WRITE");
		if (writeData(currentCs) <= 0) {
			closeFile(currentCs);
			state = STATE_DST_CLOSE;
		}
		return 0;

	case STATE_DST_CLOSE: {
//		logme(L_ERROR, "STATE_DST_CLOSE");
		erase();
		printStats(true);

		if (k != SSH_FXP_STATUS) {
			logme(L_ERROR, "closing `%s` failed: %ld", currentCs->dst, getInt32(p));
			return -1;
		}
DstDone:
		stack.pop();
		delete currentCs;
		if (stack.getCount()) {
			currentCs = stack.peek();
			if (currentCs->localDir) {
				goto ExamineNext;
			}
			logme(L_ERROR, "can't happen!? but localDir flag is not set");
		}
		stopped = 1;
		return 0;
	}
	case STATE_SRC_OPENDIR:
		if (k != SSH_FXP_HANDLE) {
			logme(L_ERROR, "can't read remote dir `%s`", currentCs->src);
			return -1;
		}

		// copy the handle
		currentCs->handleSize = getInt32(p); p += 4;
		if (p + currentCs->handleSize - length > data)
			return -1;

		currentCs->handle = malloc(currentCs->handleSize);
		memcpy(currentCs->handle, p, currentCs->handleSize);

		state = STATE_SRC_READDIR;
		readDir(currentCs);
		return 0;
	case STATE_SRC_READDIR:
		if (k != SSH_FXP_NAME) {
			logme(L_ERROR, "can't read remote dir `%s`", currentCs->src);
			return -1;
		}
		{
			uint32_t count = getInt32(p); p += 4;
			if (count == 0) {
				state = STATE_SRC_CLOSEDIR;
				closeFile(currentCs);
				return 0;
			}

			currentCs->entries = new Stack<CopyState>(count);
			if (currentCs->entries == 0)
				return -1;

			// copy responses
			for (int i = 0; i < count; ++i) {
				uint8_t * name = sshString(p);
				if (p < buffer || p - length > data)
					return -1;
				sshString(p); // skip long name
				if (p < buffer || p - length > data)
					return -1;

				if (strcmp(".", (char *)name) && strcmp("..", (char *)name) &&
						(!pattern || 0 == fnmatch(pattern, (char *)name, FNM_IGNORECASE))) {
					CopyState * cs = new CopyState(false,
							concatPath(currentCs->src, (char *)name),
							concatPath(currentCs->dst, (char *)name),
							0, 0);
					if (cs == 0)
						return -1;
					cs->srcIsDir = cs->setAttrs(p);

					currentCs->entries->add(currentCs->entries->getCount(), cs);
				} else {
					CopyState::dummy.setAttrs(p);
				}
			}
		}

	HandleNext:
		if (currentCs->entries->getCount() == 0) {
			currentCs->freeEntries();
			state = STATE_SRC_CLOSEDIR;
			closeFile(currentCs);
			return 0;
		}
		{
			// push next entry
			uint32_t idx = currentCs->entries->getCount();
			CopyState * cs = currentCs->entries->remove(idx - 1);
			stack.add(stack.getCount(), cs);
			currentCs = cs;
		}
		goto OpenRemoteDirOrFile;

	case STATE_STAT_DSTDIR:
		if (k != SSH_FXP_ATTRS) {
			logme(L_ERROR, "can't create dir `%s`: %ld", currentCs->dst, getInt32(p));
			return -1;
		}
		if (!CopyState::dummy.setAttrs(p)) {
			logme(L_ERROR, "`%s` is a file", currentCs->dst);
			return -1;
		}
		logme(L_DEBUG, "remote dir already exists: %s", currentCs->dst);
		k = SSH_FXP_STATUS;
		putInt32AndInc(p, SSH_FX_OK); p -= 4;
		/* no break */

	case STATE_DST_MKDIR:
		if (k != SSH_FXP_STATUS || getInt32(p) != SSH_FX_OK) {
			// check if dir exists
			getLStat(currentCs->dst);
			state = STATE_STAT_DSTDIR;
			return 0;
		}
ExamineNext:
		if (ExNext(currentCs->localDir, &currentCs->fib)) {
			if (pattern && fnmatch(pattern, currentCs->fib.fib_FileName, FNM_IGNORECASE))
				goto ExamineNext;
#ifndef __AMIGA__
			if (0 == strcmp(currentCs->fib.fib_FileName, ".") || 0 == strcmp(currentCs->fib.fib_FileName, ".."))
				goto ExamineNext;
#endif

			char * src = concatPath(currentCs->src, currentCs->fib.fib_FileName);
			bool isDir;
			if (IS_LINK(currentCs->fib)) {
				// link, try to open it as file
				FPTR lock = LockF(src, MODE_OLDFILE);
				if (!lock) {
					logme(L_INFO, "skipping linked folder %s", src);
					goto ExamineNext;
				}
				logme(L_INFO, "copying linked file %s", src);
				UnLockF(lock);
				isDir = false;
			} else {
				isDir = !IS_FILE(currentCs->fib);
			}

			CopyState * cs = new CopyState(isDir, src,
					concatPath(currentCs->dst, currentCs->fib.fib_FileName), 0, 0);
			if (!cs)
				return -1;

			stack.add(stack.getCount(), cs);
			currentCs = cs;
			goto OpenLocalDirOrFile;
		}
		goto DstDone;
	}

	return -1;
}

bool ScpChannel::start() {
	logme(L_DEBUG, "starting sftp channel");
	// open new channel
	if (pty) {
		logme(L_DEBUG, "opening pty");
		if (!sendNewPty())
			return false;
		if (!receiveEncryptedPacket())
			return false;
		if (buffer[5] != SSH_MSG_CHANNEL_SUCCESS)
			return false;
	}

	// open the sftp
	uint8_t *p = buffer + 5;
	*p++ = SSH_MSG_CHANNEL_REQUEST;
	putInt32AndInc(p, getChannelNo());
	putString(p, "subsystem");
	*p++ = 1;
	putString(p, "sftp");

	if (!sendEncrypted(buffer + 5, p - buffer - 5))
		return false;
	for (;;) {
		if (!receiveEncryptedPacket())
			return false;
		if (buffer[5] == SSH_MSG_CHANNEL_FAILURE)
			return false;
		if (buffer[5] == SSH_MSG_CHANNEL_SUCCESS)
			break;
	}
	// validate the copy parameters
	if (localSrc) {
		FPTR srcLock = LockF(src, SHARED_LOCK);
		if (srcLock) {
			D_S(struct FileInfoBlock, fib);
			ExamineF(srcLock, fib);
			srcIsDir = IS_DIR(*fib);
			UnLockF(srcLock);
		} else {
			char *slashColon = 0;
			char *star = 0;
			char *q = src;
			while (*q) {
				if (*q == ':' || *q == '/')
					slashColon = q;
				else if (*q == '*')
					star = q;
				++q;
			}
			if (slashColon && star > slashColon) {
				pattern = strdup (slashColon + 1);
				if (*slashColon == ':')
					++slashColon;
				*slashColon = 0;
				FPTR srcLock = LockF(src, SHARED_LOCK);
				if (srcLock)
					UnLockF(srcLock);
				else
					slashColon = 0;
			} else
				slashColon = 0;

			if (slashColon == 0) {
				logme(L_ERROR, "object not found: %s", src);
				return false;
			}
		}
	} else {
		// chk dst
		FPTR dstLock = LockF(dst, SHARED_LOCK);
		if (dstLock) {
			D_S(struct FileInfoBlock, fib);
			ExamineF(dstLock, fib);
			dstIsDir = IS_DIR(*fib);
			UnLockF(dstLock);
		} // if not exist, assume it's a dir
		char *slashColon = 0;
		char *star = 0;
		char *q = src;
		while (*q) {
			if (*q == ':' || *q == '/')
				slashColon = q;
			else if (*q == '*')
				star = q;
			++q;
		}
		if (slashColon && star > slashColon) {
			pattern = strdup (slashColon + 1);
			if (*slashColon == ':')
				++slashColon;
			*slashColon = 0;
		}
	}
	state = STATE_INIT;
	init();
	return true;
}

static bool firstDone;
static int lastPos;

static struct DateStamp now;
static struct DateStamp startTime;
static struct DateStamp lastTime;
static void erase() {
	for (short i = 36; i > 0; --i) {
		putchar('\b');
	}
}

// update information on the console
// 35 chars
// 67%   6944KB 624.4KB/s 00:05 ETA
static void printStats(bool full) {
	int percent = 100;
	if (currentCs->size) {
		if (currentCs->size > 0xffffffffUL / 100)
			percent = currentCs->pos / (currentCs->size / 100);
		else
			percent = 100 * currentCs->pos / currentCs->size;
	}
	full |= currentCs->pos == currentCs->size;

	int sz = currentCs->pos / 1000;
	if (lastPos > currentCs->pos)
		lastPos = 0;
	struct DateStamp * then;
	if (full)
		then = &startTime;
	 else
		then = &lastTime;
	int delta = delta_ms(now, *then) / 10;

	int speed = 0;
	if (delta) {
		if (full)
			speed = currentCs->size / delta;
		else
			speed = (currentCs->pos - lastPos) / delta;
	}

	lastPos = currentCs->pos;

	int eta;
	if (speed == 0) {
		eta = 0;
	} else if (full) {
		eta = delta / 100;
	} else {
		eta = ((currentCs->size - currentCs->pos) / 100) / speed;
	}
	int min = eta / 60;
	int sec = eta % 60;
	int kb = speed/10;
	printf("%3ld%% %8ldKB %4ld.%ldKB/s %2ld:%02ld %s", percent, sz, kb, speed - 10*kb, min, sec, full ? "   " : "ETA");
	if (full)
		printf("\r\n");
	fflush(stdout);
}

static void updateStats() {
	DateStampF(&now);
	if (currentCs->pos == 0) {
		if (!firstDone) {
			firstDone = true;
			startTime = now;

			if (currentCs->srcIsDir)
				currentCs->pos = currentCs->size = 0;

			numCols = 80;
			getConsoleSize();

			// print name and fill with spaces
			printf("%s", currentCs->src);
			short spaces = numCols - 37 - strlen(currentCs->src);
			if (spaces <= 0)
				spaces = 1;
			while (--spaces >= 0) {
				printf(" ");
			}
			printStats(false);

			lastPos = 0;
			lastTime = now;
		}
	} else {
		firstDone = false;

		if (currentCs->srcIsDir)
			return;

		// update every second
		long diff_ms = delta_ms(now, lastTime);
		if (diff_ms < 0 || diff_ms > 1000) {
			erase();
			printStats(false);
			lastTime = now;
		}
	}
}

void handleKeyboard() {
	if (currentCs)
		updateStats();

	if (WaitForChar(stdinBptr, 1) == DOSTRUE) {
		Read(stdinBptr, buffer, 1);
		if (*buffer == 3) {
			puts("CTRL+C");

			for (int i = 0; i < stack.getCount(); ++i) {
				CopyState * cs = stack[i];
				if (cs->handle)
					theSCP->closeFile(cs);
			}

			stopped = 1;
		}
	}
}

static void printUsage() {
	puts(__VERSION);
	puts("USAGE: amigascp [options] [source] [target]");
	puts("    one of [source]/[target] must be remote, the other local");
	puts("    -?            display this help");
	puts("    -c <file>     select the config file");
	printf("                  defaults to %s.ssh/ssh_config\n", sshDir);
	puts("    -i <file>     select the private key file for public key authentication");
	puts("    -p <port>     connect to the host at port <port>");
	puts("    -t            allocate a pseudo terminal");
	puts("    -u <user>     connect as <user>");
	puts("                  or use <user>@<host>:<path>");
	puts("    -v <n>        set verbosity, defaults to 4 = INFO");
	puts("    --ciphers <n> use the ciphers in the given order:");
	puts("                  1=aes128-gcm, 2=chacha20-poly1305");
	puts("                  defaults to n=21");
}

static void parseParams(unsigned argc, char **argv) {
	char *user = getenv("USER");
	if (user)
		username = user;

	unsigned normal = 0;
	char *arg = 0;

	if (argc == 1)
		goto usage;

	for (unsigned i = 1; i < argc; ++i) {
		arg = argv[i];
		if (normal == 0 && arg[0] == '-') {
			switch (arg[1]) {
			case '?':
				goto usage;
			case 'c':
				if (arg[2]) {
					configFile = &arg[2];
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				configFile = argv[++i];
				continue;
			case 'i':
				if (arg[2]) {
					keyFile = &arg[2];
					keyfileSet = 1;
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				keyFile = argv[++i];
				keyfileSet = 1;
				continue;
			case 'p':
				if (arg[2]) {
					port = atoi(&arg[2]);
					portSet = 1;
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				port = atoi(argv[++i]);
				portSet = 1;
				continue;
			case 't':
				pty = true;
				continue;
			case 'v':
				if (arg[2]) {
					setLogLevel((DebugLevel) atoi(&arg[2]));
					loglevelSet = 1;
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				setLogLevel((DebugLevel) atoi(argv[++i]));
				loglevelSet = 1;
				continue;
			case 'u':
				if (arg[2]) {
					username = &arg[2];
					usernameSet = 1;
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				username = argv[++i];
				usernameSet = 1;
				continue;
			case '-':
				if (0 == strncmp(arg, "--ciphers", 9)) {
					if (arg[9]) {
						encOrder = userOrder = &arg[9];
						continue;
					}
					if (i + 1 == argc)
						goto missing;

					encOrder = userOrder = argv[++i];
					continue;
				}
				/* no break */
			default:
				goto invalid;
			}
		}

		logme(L_DEBUG, "arg %ld = %s", normal, arg);
		if (normal == 0) {
			src = arg;
		} else if (normal == 1) {
			dst = arg;
		}

		++normal;
		continue;
	}

	if (normal == 2)
		return;

	usage: printUsage();
	exit(0);

	missing: printf("missing parameter for %s\n", arg);
	exit(10);

	invalid: printf("invalid option %s\n", arg);
	exit(10);
}

static bool isLocal(char *&path) {
	char *colon = strchr(path, ':');
	if (!colon)
		return true;

	// extract @ -> always remote
	char *at = strchr(path, '@');
	if (at && at < colon) {
		int l = at - path;
		char * q = (char*) malloc(l + 1);
		if (!q)
			exit(10);
		strncpy(q, path, l);
		q[l] = 0;
		username = q;

		l = colon - at - 1;
		q = (char*) malloc(l);
		if (!q)
			exit(10);
		strncpy(q, at + 1, l);
		q[l] = 0;
		hostname = q;

		path = colon + 1;
		return false;
	}


	int l = colon - path;
	char *p = (char*) malloc(l + 1);
	if (!p)
		exit(10);
	strncpy(p, path, l);
	p[l] = 0;
	char * maybeHostname = p;

#ifdef __AMIGA__
	struct DosList *dl = AttemptLockDosList(LDF_ALL | LDF_READ);
	if (!dl)
		return false;

	while (0 != (dl = NextDosEntry(dl, LDF_ALL))) {
		char *n = (char*) BADDR(dl->dol_Name) + 1;
		if (0 == stricmp(maybeHostname, n))
			break;
	}
	UnLockDosList(LDF_ALL | LDF_READ);
	if (dl)
		return true;
#endif

	path = colon + 1;
	hostname = maybeHostname;
	return false;
}

bool addForwardAcceptor(char const *s) {
	// dummy
	return false;
}

extern void parseConfigFile(int ssh);

char __stdiowin[128] = "CON://///AUTO/CLOSE/WAIT";
__stdargs int main(int argc, char **argv) {
	logme(L_FINE, __VERSION);

	parseParams(argc, argv);

	bool localSrc = isLocal(src);
	bool localDst = isLocal(dst);
	logme(L_DEBUG, "user=%s host=%s src=%s slocal=%ld dst=%s dlocal=%ld", username, hostname, src, localSrc, dst, localDst);

	if (!localSrc && !localDst) {
		puts("copying remote to remote is not supported");
		return 100;
	}
	if (localSrc && localDst) {
		puts("copying local to local is not supported");
		return 100;
	}

	parseConfigFile(false);

	theSCP = new ScpChannel(pty, localSrc, src, dst);
	clientChannels.add(0, theSCP);

	runClient();

	while (stack.getCount()) {
		CopyState * cs = stack.pop();
		delete cs;
	}

	if (firstDone)
		puts("");

	return error;
}
