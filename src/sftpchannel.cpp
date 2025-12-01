/* bebbossh - SFTP channel implementation
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
 * Project: bebbossh - SFTP server/client for Amiga
 * Purpose: Handle SFTP protocol messages, file/directory operations, and attributes
 *
 * Features:
 *  - SSH_FXP_VERSION negotiation and capability advertisement
 *  - Handle management, NAME responses, and STATUS replies
 *  - Attribute conversion between AmigaDOS and SSH2 filexfer formats
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Integrates with AmigaDOS (locks, BPTR, FileInfoBlock) and bsdsocket.library.
 *
 * Author's intent:
 *  Provide a robust, maintainable SFTP channel layer for secure file operations
 *  on classic Amiga systems, with explicit resource handling and clarity.
 * ----------------------------------------------------------------------
 */
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <time.h>

#ifdef __AMIGA__
#include <amistdio.h>
#include <dos/dos.h>
#include <proto/dos.h>
#include <proto/exec.h>

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

extern "C" { void xfree(void * ptr); }
#else
#include "amiemul.h"
#endif

#undef printf
#define printf(...)

#include <log.h>
#include <rand.h>
#include <ssh.h>
#include <test.h>

#include <sshsession.h>
#include "sftp.h"
#include "channel.h"
#include "sftpchannel.h"

#define NAMEWIDTH 24

#ifdef __AMIGA__
static inline int flags2mode(int flags) {
	if (flags & SSH2_FXF_CREAT)
		return MODE_NEWFILE;
	if (flags & SSH2_FXF_WRITE)
		return MODE_READWRITE;
	return MODE_OLDFILE;
}
#else
static inline char const * flags2mode(int flags) {
	if (flags & SSH2_FXF_CREAT)
		return MODE_NEWFILE;
	if (flags & SSH2_FXF_WRITE)
		return MODE_READWRITE;
	return MODE_OLDFILE;
}
#endif

#if 0
static uint8_t sftp_ssh_fxp_version[13] = { 0, 0, 0, 9, // size
		0, 0, 0, 5, // size - 4
		SSH_FXP_VERSION, 0, 0, 0, 3, // version 3
		};
#else
static uint8_t sftp_ssh_fxp_version[40] = { 0, 0, 0, 36, // size
		0, 0, 0, 32, // size - 4
		SSH_FXP_VERSION, 0, 0, 0, 3, // version 3
		0, 0, 0, 18, 'l', 'i', 'm', 'i', 't', 's', '@', 'o', 'p', 'e', 'n', 's', 's', 'h', '.', 'c', 'o', 'm',
		0, 0, 0, 1, '1'
		};
#endif

static uint8_t success_msg[11] = { 0, 0, 0, 7, // size
		'S', 'u', 'c', 'c', 'e', 's', 's' };

static uint8_t eof_msg[15] = { 0, 0, 0, 11, // size
		'E', 'n', 'd', ' ', 'o', 'f', ' ', 'f', 'i', 'l', 'e' };

static uint8_t no_such_path_msg[7] = { 0, 0, 0, 3, 'n', 'i', 'x' };

static uint8_t uhm[7] = { 0, 0, 0, 3, 'u', 'h', 'm' };


Handle::Handle(char const* name, BPTR file_, DPTR dir_, uint32_t id_)
: filename(strdup(name)), file(file_), dir(dir_), idx(id_),
  first(true), eof(false)
{
	randfill(handle, sizeof(handle));
	memset(&fib, 0xff, sizeof(fib));
}
Handle::~Handle() {
	if (file) {
		printf("close file %08lx\n", file);
		Close(file);
	}
	if (dir) {
		printf("unlock dir %08lx\n", dir);
		UnLock(dir);
	}
	free(filename);
}


SftpChannel::SftpChannel(SshSession *server, uint32_t channel) :
		Channel(server, channel, C_FORWARD), requestId(0), flags(0), limit(MAXPACKET),
		handles(32), queue(0), queueLen(0) {
}

SftpChannel::~SftpChannel() {
	for (int i = 0; i < handles.getMax(); ++i) {
		Handle * h = handles[i];
		delete h;
	}
}

void SftpChannel::abort() {
	close();
}

void SftpChannel::close() {
	server->closeChannel(this);
}

void SftpChannel::newHandle(uint8_t * &q, uint8_t const * path, BPTR file, DPTR dir) {
	Handle * h = new Handle((char *)path, file, dir, handles.getFreeIndex());

	*q++ = SSH_FXP_HANDLE;
	putInt32AndInc(q, requestId);

	// copy random handle + counted ID
	putInt32AndInc(q, sizeof(h->handle) + 4);
	memcpy(q, h->handle, sizeof(h->handle) + 4);
	q += sizeof(h->handle) + 4;

	handles.add(h->idx, h);
}

Handle * SftpChannel::findHandle(uint8_t * hdata) const {
	for (int i = 0; i < handles.getMax(); ++i) {
		Handle * h = handles[i];
		if (!h)
			continue;
		if (0 == memcmp(hdata, h->handle, sizeof(h->handle) + 4))
			return h;
	}
	return 0;
}

int SftpChannel::processSocketData(void *data, int len) {
	logme(L_FINE, "@%ld:%ld sending %ld bytes", server->getSockFd(), channel, len);
	return server->channelWrite(channel, data, len);
}

void SftpChannel::makeStatus(uint8_t * &q, uint32_t result) {
	*q++ = SSH_FXP_STATUS;
	putInt32AndInc(q, requestId);
	putInt32AndInc(q, result);
//	logme(L_DEBUG, "status=%ld", result);
	switch (result) {
	case SSH_FX_OK:
		memcpy(q, success_msg, sizeof(success_msg));
		q += sizeof(success_msg);
		break;
	case SSH_FX_EOF:
		memcpy(q, eof_msg, sizeof(eof_msg));
		q += sizeof(eof_msg);
		break;
	case SSH_FX_NO_SUCH_PATH:
		memcpy(q, no_such_path_msg, sizeof(no_such_path_msg));
		q += sizeof(no_such_path_msg);
		break;
	default:
		memcpy(q, uhm, sizeof(uhm));
		q += sizeof(uhm);
		break;
	}
	putInt32AndInc(q, 0); // error message lang
}

bool sanitize(char * path) {
	char * colon = strchr(path, ':');
	if (colon) {
		// two colons?
		char * rcolon = strrchr(path, ':');
		if (rcolon != colon) {
			// discard leading part
			while (rcolon[-1] != '/' && rcolon[-1] != ':')
				--rcolon;
			strcpy(path, rcolon);
		}
	}

	if (colon && colon > path) {
#ifdef __AMIGA__
		struct DosList * dl = AttemptLockDosList(LDF_ALL | LDF_READ);
		if (!dl)
			return false;

		char x = *colon;
		*colon = 0;

		while ( 0 != (dl = NextDosEntry(dl, LDF_ALL))) {
			char * n = (char *)BADDR(dl->dol_Name) + 1;
			if (0 == stricmp(path, n))
				break;
		}
		UnLockDosList(LDF_ALL | LDF_READ);
		*colon = x;
		if (!dl)
#endif
			return false;
	}
	return true;
}

bool normalize(uint8_t * path_) {
	char * path = (char *)path_;
	logme(L_FINE, "in: %s", path);

	if (path[0] == '.') {
		if (path[1] == '/')
			strcpy(path, path + 2);
		else
			strcpy(path, path + 1);
	}

	char *colon = strchr(path, ':');
	if (colon && colon[1] == '/')
		strcpy(colon + 1, colon + 2);
	char * end = path + strlen(path);
	if (end > path && end[-1] == '/')
		end[-1] = 0;

	if (path[0] == '/')
		path[0] = ':';

	if (!sanitize(path))
		return false;

	logme(L_FINE, "ou: %s", path);
	return true;
}


void putFib(uint8_t * & q, struct FileInfoBlock * fib) {
	uint32_t flags = SSH2_FILEXFER_ATTR_ACMODTIME | SSH_FILEXFER_ATTR_PERMISSIONS | SSH2_FILEXFER_ATTR_UIDGID;
	uint32_t mode = a2sshmode(fib->fib_Protection);
	if (IS_FILE(*fib)) { // file
		flags |= SSH_FILEXFER_ATTR_SIZE;
		mode |= 0100000;
	} else if (IS_LINK(*fib)) { // link
		flags |= SSH_FILEXFER_ATTR_SIZE;
		mode |= 0120000;
	} else if (IS_DIR(*fib)) { // folder
		mode |= 040000;
	}
	// put attrs
	putInt32AndInc(q, flags); // flags

	if (flags & SSH_FILEXFER_ATTR_SIZE) {
		putInt32AndInc(q, 0);
		putInt32AndInc(q, fib->fib_Size);
	}

	// fake uid gid
	putInt32AndInc(q, fib->fib_OwnerUID);
	putInt32AndInc(q, fib->fib_OwnerGID);

	putInt32AndInc(q, mode);

	struct timeval nowtime;
#ifdef __AMIGA__
	struct DateStamp *stamp = &fib->fib_Date;
	long s = stamp->ds_Tick/ TICKS_PER_SECOND;
	nowtime.tv_sec = (stamp->ds_Days * 24 * 60 + stamp->ds_Minute) * 60 + _timezone + s + 252460800;
	nowtime.tv_usec = stamp->ds_Tick * (1000000 / TICKS_PER_SECOND) - s * 1000000;
#else
	// fill timeval from stat
	nowtime.tv_sec  = fib->st.st_mtime;                  // modification time in seconds
	nowtime.tv_usec = fib->st.st_mtim.tv_nsec / 1000;    // convert nanoseconds -> microseconds
#endif
	// modtime
	putInt32AndInc(q, nowtime.tv_usec);
	putInt32AndInc(q, nowtime.tv_sec);
}

void setAttrs(uint8_t * p, uint8_t * path) {
	uint32_t flags = getInt32(p);
	p += 4;

	if (flags & SSH_FILEXFER_ATTR_SIZE)
		p += 8;
	if (flags & SSH_FILEXFER_ATTR_ALLOCATION_SIZE)
		p += 8;
	if (flags & SSH_FILEXFER_ATTR_OWNERGROUP) {
		uint32_t l = getInt32(p); // skip owner
		p += l + 4;
		l = getInt32(p);	// skip group
		p += l + 4;
	}

	if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
		uint32_t protect = getInt32(p);
		p += 4;
		SetProtection((char* )path, ssh2amode(protect));
	}
	struct timeval tv;
	if (flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		tv.tv_usec = getInt32(p);
		p += 4;
		tv.tv_sec = getInt32(p);
		p += 4;

	    // normalize overflow
		unsigned long u = tv.tv_usec / 1000000; // get overflow micros
		tv.tv_usec -= u * 1000000;
		tv.tv_sec += u;

#ifdef __AMIGA__
		struct DateStamp date;

		tv.tv_sec -= 252460800;        // amiga offset in seconds
		tv.tv_sec -= _timezone;

		date.ds_Days = tv.tv_sec / (24 * 60 * 60);
		tv.tv_sec -= date.ds_Days * (24 * 60 * 60);
		date.ds_Minute = tv.tv_sec / 60;
		tv.tv_sec -= date.ds_Minute * 60;
		date.ds_Tick = tv.tv_usec / (1000000 / TICKS_PER_SECOND) + tv.tv_secs * TICKS_PER_SECOND;

		SetFileDate((char* )path, &date);
#else
		struct timespec times[2];
		times[0].tv_sec  = tv.tv_sec;
		times[0].tv_nsec = tv.tv_usec * 1000;
		times[1].tv_sec  = tv.tv_sec;
		times[1].tv_nsec = tv.tv_usec * 1000;

		utimensat(AT_FDCWD, (char *)path, times, 0);
#endif
#if 0
		struct DateStamp * stamp = &date;
		time_t nowtime = ((stamp->ds_Days + 2922)* 24 * 60 + stamp->ds_Minute ) * 60
				+ stamp->ds_Tick/ TICKS_PER_SECOND;
		struct tm tm;
		gmtime_r(&nowtime, &tm);
		char to[36];
		strftime(to, 32, "%d-%h-%Y %H:%M:%S", &tm);
		logme(L_ERROR, "-> %s %s", to, path);
#endif
	}
}

void SftpChannel::makeNameResponse(uint8_t * &q, char const * path, struct FileInfoBlock *fib) {
	// create a data response
//	logme(L_FINE, "@%ld:%ld SSH_FXP_NAME %s", server->getSockFd(), channel, path);

	short l = strlen(path);
	putInt32AndInc(q, l);
	memcpy(q, path, l);
	q += l;


	// long name
	char * ln = (char *)q + 4;
	l = strlen(fib->fib_FileName);
	memcpy(ln, fib->fib_FileName, l);
	char * to = ln + l;
	if (NAMEWIDTH - l > 0) {
		memset(to, ' ', NAMEWIDTH - l);
		to = ln + NAMEWIDTH;
	}
	*to ++= ' ';
	if (fib->fib_DirEntryType == 3) {
		strcpy(to, "      Link");
		to += 10;
	} else
	if (fib->fib_DirEntryType >= 0) {
		strcpy(to, "       Dir");
		to += 10;
	} else {
		to += snprintf(to, 16, "%10ld", fib->fib_Size);
	}
	*to ++= ' ';
#ifdef __AMIGA__
    // Amiga protection bits
    *to++ = (fib->fib_Protection & FIBF_HOLD)    ? 'h' : '-';
    *to++ = (fib->fib_Protection & FIBF_SCRIPT)  ? 's' : '-';
    *to++ = (fib->fib_Protection & FIBF_PURE)    ? 'p' : '-';
    *to++ = (fib->fib_Protection & FIBF_ARCHIVE) ? 'a' : '-';
    *to++ = !(fib->fib_Protection & FIBF_READ)    ? 'r' : '-';
    *to++ = !(fib->fib_Protection & FIBF_WRITE)   ? 'w' : '-';
    *to++ = !(fib->fib_Protection & FIBF_EXECUTE) ? 'e' : '-';
    *to++ = !(fib->fib_Protection & FIBF_DELETE)  ? 'd' : '-';
#else
    // Linux: map POSIX mode bits
    mode_t m = fib->fib_Protection; // mapped from st_mode
    *to++ = (m & S_ISUID) ? 'h' : '-'; // placeholder for Amiga "hold"
    *to++ = (m & S_IXUSR) ? 's' : '-'; // exec bit ~ script
    *to++ = (m & S_ISVTX) ? 'p' : '-'; // sticky ~ pure
    *to++ = (m & S_IFMT)  ? 'a' : '-'; // archive flag not present, placeholder
    *to++ = (m & S_IRUSR) ? 'r' : '-';
    *to++ = (m & S_IWUSR) ? 'w' : '-';
    *to++ = (m & S_IXUSR) ? 'e' : '-';
    *to++ = (m & S_IFMT)  ? 'd' : '-'; // delete not present, placeholder
#endif
    *to ++= ' ';

#ifdef __AMIGA__
    struct DateStamp *stamp = &fib->fib_Date;
    time_t nowtime = ((stamp->ds_Days + 2922) * 24 * 60 + stamp->ds_Minute) * 60
                   + stamp->ds_Tick / TICKS_PER_SECOND;
#else
    // Linux: use st_mtime directly
    time_t nowtime = fib->fib_Date; // mapped to st.st_mtime in amiemul.h
#endif

	struct tm tm;
	gmtime_r(&nowtime, &tm);

	strftime(to, 32, "%d-%h-%Y %H:%M:%S", &tm);
	to += strlen(to);

	l = to - ln;
	putInt32AndInc(q, l);
	q += l;

	putFib(q, fib);
}

void SftpChannel::sendPacket(uint8_t *end, uint8_t * &out) {

	int innerLen = end - out - 4;
	uint8_t * q = out;
	putInt32AndInc(q, innerLen);

	uint8_t * const outer = (uint8_t*) server->outdata + 5;
	int packetLen = end - outer - 9; // SSH_MSG_CHANNEL_DATA + channelNo + packetLen

	if (packetLen + 32 < limit) { // combine responses
		logme(L_FINE, "try combine packet at %ld %08lx", packetLen, end);
		out = end;
		return;
	}

	logme(L_DEBUG, "@%ld:%ld sftp reply %ld bytes", server->getSockFd(), channel, innerLen);

	int rest = 0;
	if (packetLen > limit) {
		rest = packetLen - limit;
		packetLen = limit;
	}

	uint8_t * g = outer + 5;
	putInt32AndInc(g, packetLen); // outer length

	if (rest) {
		// keep the data - copy needed since send trashes it
		if (queueLen < rest) {
			xfree(queue);
			queue = malloc(rest);
			queueLen = rest;
		}
		memcpy(queue, g + limit, rest);
	}

	packetLen += 9;
//	_dump("SEND", outer, packetLen > 64 ? 64 : packetLen);
	server->write(outer, packetLen); // this trashes the out data!

	out = outer;
	*out++ = SSH_MSG_CHANNEL_DATA;
	putInt32AndInc(out, channel);
	out += 4; // skip outer len

	if (rest) {
//		logme(L_ERROR, "keep rest %ld", rest);
		memcpy(out, queue, rest);
		out += rest;

		if (rest + 100 > limit) {
			flush(out);
			*out++ = SSH_MSG_CHANNEL_DATA;
			putInt32AndInc(out, channel);
			out += 4; // skip outer len
		}
	}
}
/**
 * Handle the channel data as SFTP packets.
 * @params
 * 	data		pointer to the data
 * 	outerLen	length of the data
 *
 * @return
 * 	< 0 on error -> abort
 * 	>= 0 the count of not processed data
 */
int SftpChannel::handleData(char *data, unsigned outerLen) {
	logme(L_FINE, "@%ld:%ld sftp handle %ld bytes", server->getSockFd(), channel, outerLen);

//	_dump("data", data, outerLen > 64 ? 64 : outerLen);

	uint8_t * out = (uint8_t*) server->outdata + 5;
	*out++ = SSH_MSG_CHANNEL_DATA;
	putInt32AndInc(out, channel);
	out += 4; // skip outer len

	// handle all requests
	for (uint8_t *p0 = (uint8_t*) data; p0 < (uint8_t*)data + outerLen;) {
		int avail = (uint8_t*)data + outerLen - p0;
		if (avail < 4) {
			flush(out);
			logme(L_FINE, "remaining data far too small: %ld, keep it for next request", avail);
			return avail;
		}
		uint8_t *p = p0;
		uint32_t packetLen = getInt32(p); // goto next packet

		if (avail < packetLen + 4) {
			flush(out);
			logme(L_FINE, "remaining data too small: %ld, keep it for next request", avail);
			return avail;
		}

		p0 += packetLen + 4;
		p += 4;

		logme(L_FINE, "processing part: %ld, next=%08lx, end=%08lx", packetLen, p0, data + outerLen);

		uint8_t *q = out + 4; // behind innerLen

		uint8_t k = *p++;
		requestId = getInt32(p);
		p += 4;

		uint32_t result = SSH_FX_FAILURE;

		Handle * handle;

		// if file is used do a check
		switch (k) {
		case SSH_FXP_CLOSE:
		case SSH_FXP_READ:
		case SSH_FXP_WRITE:
		case SSH_FXP_FSTAT:
		case SSH_FXP_FSETSTAT:
		case SSH_FXP_READDIR: {
			uint8_t *inHandle = sshString(p);
			if (p > p0) // out of bounds
				return -1;

			handle = findHandle(inHandle);

			if (handle == 0) {
				result = SSH_FX_INVALID_HANDLE;
				goto Status;
			}
			if (k != SSH_FXP_CLOSE) {
				if (k == SSH_FXP_READDIR && handle->dir == 0) {
					result = SSH_FX_INVALID_HANDLE;
					goto Status;
				}
				if (k != SSH_FXP_READDIR && handle->file == 0) {
					result = SSH_FX_INVALID_HANDLE;
					goto Status;
				}
			}
		}
			break;
		default:
			handle = 0;
		}

		switch (k) {
		case SSH_FXP_INIT:
			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_INIT", server->getSockFd(), channel);
			memcpy(q - 8, sftp_ssh_fxp_version, sizeof(sftp_ssh_fxp_version));
			server->write(server->outdata + 5, sizeof(sftp_ssh_fxp_version) + 5);
			return 0;

		case SSH_FXP_OPEN: {
			uint8_t *path = sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;

			if (!normalize(path)) {
				result =  SSH_FX_NO_SUCH_PATH;
				goto Status;
			}

			flags = getInt32(p);
			p += 4;
			auto mode = flags2mode(flags);

			if (flags & SSH2_FXF_EXCL) {
				FPTR lock = LockF((char* )path, SHARED_LOCK);
				if (lock) {
					UnLockF(lock);
					result =  SSH_FX_FILE_ALREADY_EXISTS;
					goto Status;
				}
			}

			// ignore attrs which might follow

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_OPEN for %s flags=%ld->mode=%ld", server->getSockFd(), channel, path, flags, mode);

			BPTR file = Open((char* )path, mode);

			if (file && mode == MODE_NEWFILE) { // reopen shared
				Close(file);
				file = Open((char* )path, MODE_READWRITE);
			}

			if (file == 0) {
				result =  SSH_FX_NO_SUCH_FILE;
				goto Status;
			}

			newHandle(q, path, file, 0);
			break;
		}

		case SSH_FXP_OPENDIR: {
			uint8_t *path = sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;

			if (!normalize(path)) {
				result =  SSH_FX_NO_SUCH_PATH;
				goto Status;
			}

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_OPENDIR for %s", server->getSockFd(), channel, path);

			DPTR dir = Lock((char *)path, SHARED_LOCK);
printf("locked dir %s = %08lx\n", path, dir);

			if (dir == 0) {
				result = SSH_FX_NOT_A_DIRECTORY;
				goto Status;
			}

			newHandle(q, path, 0, dir);
			break;
		}

		case SSH_FXP_READDIR: {
			// the dir itself
			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_READDIR for %s id=%ld %08lx key=%ld", server->getSockFd(), channel, handle->filename,
					handle->idx, &handle->fib, handle->fib.fib_DiskKey);

//			_dump("fib", &handle->fib, sizeof(struct FileInfoBlock));

			if (handle->first) {
				handle->first = false;
				logme(L_FINE, "Examine first dir %08lx\n", handle->dir);
				if (!Examine(handle->dir, &handle->fib))
					goto Status;
			}

			*q++ = SSH_FXP_NAME;
			putInt32AndInc(q, requestId);

			// count
			uint8_t * countPos = q;
			q = countPos + 4;
			uint32_t count = 0;

			if (!handle->eof)
			for(;;) {
				logme(L_FINE, "ExNext dir %08lx\n", handle->dir);
				if (!ExNext(handle->dir, &handle->fib)) {
					handle->eof = true;
					break;
				}
				++count;
				makeNameResponse(q, handle->fib.fib_FileName, &handle->fib);

				if (q - out + 512 > limit)
					break;
			}

			// send a SSH_FXP_NAME if there are handles
			if (count) {
				logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_READDIR with %ld names", server->getSockFd(), channel, count);
				putInt32AndInc(countPos, count);
				break;
			}

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_READDIR EOF", server->getSockFd(), channel);
			result =  SSH_FX_EOF;
			goto Status;
		}

		case SSH_FXP_CLOSE: {
			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_CLOSE for %s", server->getSockFd(), channel, handle->filename);

			if (handles.remove(handle->idx)) {
				delete handle;
			}

			result = SSH_FX_OK;
			goto Status;
		}

		case SSH_FXP_READ: {
			p += 4; // no support for >4GB
			uint32_t offset = getInt32(p);
			p += 4;
			uint32_t len = getInt32(p);
			if (p > p0) // out of bounds
				return -1;

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_READ for %s @%ld:%ld", server->getSockFd(), channel, handle->filename, offset, len);

			// create a data response
			*q++ = SSH_FXP_DATA;
			putInt32AndInc(q, requestId);

			// test for EOF
			uint32_t oldPos = Seek(handle->file, 0, OFFSET_END);
			uint32_t end = Seek(handle->file, oldPos, OFFSET_BEGINNING);
			// correct the length if not enough data is there
			int delta = end - oldPos;
			if (delta < len) {
				len = delta;
			}

			uint32_t read = Read(handle->file, q + 4, len);
			// handle EOF
			if (read == 0) {
				q -= 5;
				result = SSH_FX_EOF;
				goto Status;
			}

			logme(L_FINE, "@%ld:%ld sftp SSH_FXP_READ len=%ld", server->getSockFd(), channel, len);
			putInt32AndInc(q, len); // full length, rest is sent in next packet

			q += read;
			break;
		}

		case SSH_FXP_WRITE: {
			p += 4; // no support for >4GB
			uint32_t offset = getInt32(p);
			p += 4;

			uint32_t len = getInt32(p);
			p += 4;

			logme(L_DEBUG, "@%ld:%ld:%08lx sftp SSH_FXP_WRITE for %s @%ld:%ld", server->getSockFd(), channel, requestId, handle->filename, offset, len);

			if (flags & SSH2_FXF_APPEND)
				Seek(handle->file, 0, OFFSET_END);
			else
				Seek(handle->file, offset, OFFSET_BEGINNING);

			Write(handle->file, p, len);

			result = SSH_FX_OK;
			goto Status;
		}

		case SSH_FXP_SETSTAT:
		case SSH_FXP_FSETSTAT: {
			uint8_t *path;
			if (k == SSH_FXP_FSETSTAT) {
				path = (uint8_t*) handle->filename;
			} else {
				path = sshString(p);
				if (p > p0) // out of bounds
					return -1;
			}
			if (!normalize(path)) {
				result =  SSH_FX_NO_SUCH_PATH;
				goto Status;
			}

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_SETSTAT for %s", server->getSockFd(), channel, path);

			setAttrs(p, path);

			result = SSH_FX_OK;
			goto Status;
		}

		case SSH_FXP_FSTAT:
		case SSH_FXP_STAT:
		case SSH_FXP_LSTAT: {
			uint8_t *path;

			if (k == SSH_FXP_FSTAT) {
				path = (uint8_t*) handle->filename;
			} else {
				path = sshString(p);
				if (p > p0) // out of bounds
					return -1;

				*p = 0;

				if (!normalize(path)) {
					result =  SSH_FX_NO_SUCH_PATH;
					goto Status;
				}
			}

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_STAT for %s", server->getSockFd(), channel, path);

			FPTR lock = LockF((char* )path, SHARED_LOCK);
//			logme(L_ERROR, "lock = %08lx", lock);

			if (lock) {
				D_S(struct FileInfoBlock, fib);
				ExamineF(lock, fib);
				UnLockF(lock);

				*q++ = SSH_FXP_ATTRS;
				putInt32AndInc(q, requestId); // request-id

				putFib(q, fib);
				break;
			} else
				result = SSH_FX_NO_SUCH_FILE;
			goto Status;
		}

		case SSH_FXP_MKDIR: {
			uint8_t *path = sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;
			if (!normalize(path)) {
				result =  SSH_FX_NO_SUCH_PATH;
				goto Status;
			}

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_MKDIR for %s", server->getSockFd(), channel, path);

			DPTR lock = CreateDir((char *)path);
			if (lock) {
				UnLock(lock);
				setAttrs(p, path);
				result = SSH_FX_OK;
			}
			goto Status;
		}

		case SSH_FXP_REMOVE:
		case SSH_FXP_RMDIR: {
			uint8_t *path = sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;
			if (!normalize(path)) {
				result =  SSH_FX_NO_SUCH_PATH;
				goto Status;
			}

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_REMOVE/SSH_FXP_RMDIR for %s", server->getSockFd(), channel, path);

			if (DeleteFile((char *)path))
				result = SSH_FX_OK;
			goto Status;
		}

		case SSH_FXP_REALPATH: {
			uint8_t *path = sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;

			if (!normalize(path)) {
				result =  SSH_FX_NO_SUCH_PATH;
				goto Status;
			}
			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_REALPATH for %s", server->getSockFd(), channel, path);

			D_S(struct FileInfoBlock, fib);
			FPTR lock = LockF((char *)path, SHARED_LOCK);
			printf("Lock %s %08lx\n", path, lock);
			if (lock) {
				printf("Examine %08lx\n", lock);
				ExamineF(lock, fib);
				printf("UnLock %08lx\n", lock);
				UnLockF(lock);
			} else
				memset(fib, 0, sizeof(*fib));


			*q++ = SSH_FXP_NAME;
			putInt32AndInc(q, requestId);
			putInt32AndInc(q, 1); // count of responses

			makeNameResponse(q, (char*)path, fib);
			*q++ = 1; // EOL
			break;
		}

		case SSH_FXP_READLINK: {
			uint8_t *link = sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_READLINK for %s", server->getSockFd(), channel, link);

			if (!normalize(link)) {
				result =  SSH_FX_NO_SUCH_PATH;
				goto Status;
			}

#ifdef __AMIGA__
			struct DevProc * dp = GetDeviceProc((CONST_STRPTR)link, NULL);
			while (dp) {
				uint8_t * path = q + 256;
				int len = ReadLink(dp->dvp_Port, dp->dvp_Lock, (CONST_STRPTR)link, (STRPTR)path, 255);
// logme(L_ERROR, "%s len=%ld err=%ld", link, len, IoErr());
				if (len > 0) {
					D_S(struct FileInfoBlock, fib);
					BPTR lock = Lock((char *)path, SHARED_LOCK);
					if (lock) {
						Examine(lock, fib);
						UnLock(lock);
					} else
						memset(fib, 0, sizeof(*fib));
					*q++ = SSH_FXP_NAME;
					putInt32AndInc(q, requestId);
					putInt32AndInc(q, 1); // count of responses

					makeNameResponse(q, (char*)path, fib);
					*q++ = 1; // EOL
					break;
				}
				// handle multi assign
				if (dp->dvp_Flags & DVPF_ASSIGN)
					dp = GetDeviceProc((CONST_STRPTR)link, dp);
				else {
					// not found -> release and clear
					FreeDeviceProc(dp);
					dp = NULL;
				}
			}
			if (dp) { // we got something
				FreeDeviceProc(dp);
				break;
			}
#else
		    char path[PATH_MAX];
		    ssize_t len = readlink((const char*)link, path, sizeof(path)-1);
		    if (len > 0) {
		        path[len] = '\0';
		        struct stat st;
		        struct FileInfoBlock fib;
		        if (lstat(path, &fib.st) != 0) {
		            memset(&fib, 0, sizeof(fib));
		        }
		        *q++ = SSH_FXP_NAME;
		        putInt32AndInc(q, requestId);
		        putInt32AndInc(q, 1);
		        makeNameResponse(q, path, &fib);
		        *q++ = 1;
		    } else {
		        result = SSH_FX_NO_SUCH_PATH;
		    }
#endif

			goto Status;
		}

		case SSH_FXP_SYMLINK: {
			uint8_t *link = sshString(p);
			if (p > p0) // out of bounds
				return -1;

			uint8_t *to= sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_SYMLINK for %s -> %s", server->getSockFd(), channel, link, to);

			if (!normalize(link) || !normalize(to)) {
				result = SSH_FX_NO_SUCH_PATH;
				goto Status;
			}

			if (MakeLink((char const *)to, (size_t)link, LINK_SOFT))
				result = SSH_FX_OK;
			else
				logme(L_ERROR, "can't create soft link from %s to %s", link, to);

			goto Status;
		}

		case SSH_FXP_EXTENDED: {
			uint8_t * name = sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;
			if (0 == strcmp((char *)name, "limits@openssh.com")) {
				*q++ = SSH_FXP_EXTENDED_REPLY;
				putInt32AndInc(q, 1);

				putInt32AndInc(q, 0);
				putInt32AndInc(q, 34006); // max packet

				putInt32AndInc(q, 0);
				putInt32AndInc(q, 32768 - 32); // max read
				putInt32AndInc(q, 0);
				putInt32AndInc(q, 32768 - 32); // max write
				putInt32AndInc(q, 0);
				putInt32AndInc(q, 32); // max handles
				break;
			}
			goto Status;
		}

		case SSH_FXP_RENAME: {
			uint8_t *from = sshString(p);
			if (p > p0) // out of bounds
				return -1;

			uint8_t *to= sshString(p);
			if (p > p0) // out of bounds
				return -1;
			*p = 0;

			logme(L_DEBUG, "@%ld:%ld sftp SSH_FXP_RENAME for %s -> %s", server->getSockFd(), channel, from, to);
			if (!normalize(from) || !normalize(to)) {
				result = SSH_FX_NO_SUCH_PATH;
				goto Status;
			}

			DeleteFile((STRPTR)to);
			if (Rename((STRPTR)from, (STRPTR)to))
				result = SSH_FX_OK;
			else
				logme(L_ERROR, "can't rename from %s to %s", from, to);

			goto Status;
		}

		default:
			logme(L_ERROR, "@%ld:%ld sftp unimplemented %ld", server->getSockFd(), channel, k);
			Status:
			q = out + 4;
			makeStatus(q, result);
			break;
		} // end of switch (k)

		sendPacket(q, out);
	}

	flush(out);
	return 0;
}

void SftpChannel::flush(uint8_t * out) {
	// send pending data
	int rest = out - ((uint8_t*) server->outdata + 14);
	if (rest > 0) {
		logme(L_FINE, "FLUSH %ld", rest);
		uint8_t * l = (uint8_t*)server->outdata + 10;
		putInt32AndInc(l, rest);
//		_dump("FLUSH", server->outdata + 5, rest + 9);
		server->write(server->outdata + 5, rest + 9);
	}
}
