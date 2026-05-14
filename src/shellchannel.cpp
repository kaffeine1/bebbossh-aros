/*
 * bebbossh - interactive shell channel
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
 * Purpose: Provide an interactive shell over SSH with PTY support
 *
 * Features:
 *  - Break signaling via MsgPorts and DOS packets
 *  - Local echo, prompt rendering, and autocomplete
 *  - CRLF normalization for PTY I/O
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Integrates with AmigaDOS (locks, directories), bsdsocket.library, and timer.device.
 *
 * Author's intent:
 *  Deliver a practical, maintainable shell experience on classic Amiga systems,
 *  with explicit resource management and clear flow control.
 * ----------------------------------------------------------------------
 */
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <stdlib.h>
#include "platform.h"
#if BEBBOSSH_AMIGA_API
#include <amistdio.h>

#include <dos/dosextens.h>
#include <dos/dostags.h>
#include <proto/dos.h>
#include <proto/exec.h>
#include <proto/socket.h>
#include <proto/timer.h>

#define DPTR BPTR

#else
#include "amiemul.h"

#endif

#include <log.h>
#include <sshsession.h>
#include <test.h>

#include "channel.h"
#include "shellchannel.h"

ShellChannel::ShellChannel(SshSession * server, uint32_t channel, ChannelType type)
: Channel(server, channel, type),
		pty(false), shell(false), exec(false),
		running(false), done(false),
		rows(0), cols(0),
#if BEBBOSSH_AMIGA_API
		localEcho(false),
		stackSize(::stackSize), dir(0),
		breakPort1(0), breakPort2(0), pending(0), waiting(0),
#if BEBBOSSH_AROS
		arosExecFileMode(false), arosExecTimedOut(false), arosExecRc(255),
#endif
		xpos(line), xend(line),
		inBufferLen(1024),
		history(32)
{
	*xend = 0;
#if BEBBOSSH_AROS
	arosExecOutName[0] = 0;
	arosExecArgs[0] = 0;
	arosExecCommandName[0] = 0;
	arosExecStarted.tv_secs = 0;
	arosExecStarted.tv_micro = 0;
#endif
	if (homeDir)
		dir = Lock(homeDir, SHARED_LOCK);
	if (!dir)
		dir = Lock("RAM:", SHARED_LOCK);
	logme(L_DEBUG, "@%ld:%ld opening shell channel", server->getSockFd(), channel);
	inBuffer = (char *)malloc(inBufferLen);
}
#else
	pid(0), master(0)
{
}
#endif

ShellChannel::~ShellChannel() {
#if BEBBOSSH_AMIGA_API
	free(inBuffer);
#if BEBBOSSH_AROS
	if (arosExecOutName[0])
		DeleteFile(arosExecOutName);
#endif
	if (dir)
		UnLock(dir);
#endif
	logme(L_DEBUG, "@%ld:%ld terminating shell channel", server->getSockFd(), channel);
}


#if BEBBOSSH_AMIGA_API

extern void handleMsg(struct Message * msg);

extern struct MsgPort * port;
extern struct Task * thisTask;

extern LONG readFx;
extern LONG writeFx;
extern LONG flushFx;
extern struct FileHandle *theInput;
extern long theInputSize;
extern struct FileHandle *theOutput;

extern int stopped;

struct MsgPort * ShellChannel::setBreakPort(struct MsgPort * pnew, struct MsgPort * pold) {
	struct MsgPort * r = 0;
	if (breakPort1 == pold) {
		r = breakPort1;
		breakPort1 = pnew;
	} else
	if (breakPort2 == pold) {
		r = breakPort2;
		breakPort2 = pnew;
	} else
	if (breakPort1 == 0) {
		breakPort1 = pnew;
	}
	else if (breakPort2 == 0) {
		breakPort2 = pnew;
	}
	return r;
}

int ShellChannel::read(char * to, int toReadIn) {
	int avail = getAvail();
	int toRead = (toReadIn > avail) ? avail : toReadIn;

	logme(L_DEBUG, "@%ld:%ld read want %ld, have %ld %02lx", server->getSockFd(), channel, toReadIn, avail, *line);

	if (toRead) {
	memcpy(to, line, toRead);
	xpos -= toRead;
	xend -= toRead;
	if (avail > toRead) {
		memmove(line, line + toRead, avail - toRead);
	}
	}
	return toRead;
}

int ShellChannel::write(char * from, int len) {
	logme(L_TRACE, "@%ld:%ld ShellChannel::write %ld", server->getSockFd(), channel, len);
	if (pty) {
		char * out = &server->outdata[14];
		char *to = out;
		for (int i = 0; i < len; ++i) {
			char c = *from++;
			if (c == 0xa && from[-2] != 0xd)
				*to++ = 0xd;
			*to++ = c;
			if (c == 0xd && from[0] != 0xa)
				*to++ = 0xa;
		}
		server->channelWrite(channel, out, to - out);
		return len;
	}
	return server->channelWrite(channel, from, len);
}

void ShellChannel::abort() {
	if (pending) {
		struct DosPacket *packet = getDosPacket(pending);
		logme(L_DEBUG, "@%ld:%ld abort pending read of %s %p, packet %p, port %p", server->getSockFd(), channel, getName(), pending, packet, packet->dp_Port);

		pending = 0;
		ReplyPkt(packet, DOSTRUE, ERROR_ACTION_NOT_KNOWN);
	}
	if (waiting) {
		logme(L_DEBUG, "@%ld:%ld abort WaitForChar of %s", server->getSockFd(), channel, getName());
		struct DosPacket *packet = getDosPacket(waiting);
		waiting = 0;
		ReplyPkt(packet, DOSFALSE, 0);
	}
}

void ShellChannel::checkTimeout(struct timeval * tv) {
	if (waiting && CmpTime(&until, tv) >= 0) {
		logme(L_DEBUG, "@%ld:%ld WaitForChar timeout of %s", server->getSockFd(), channel, getName());
		struct DosPacket *packet = (struct DosPacket*) waiting->mn_Node.ln_Name;
		waiting = 0;
		ReplyPkt(packet, DOSFALSE, 0);
	}
#if BEBBOSSH_AROS
	if (arosExecFileMode && running && !arosExecTimedOut) {
		LONG elapsed = tv->tv_secs - arosExecStarted.tv_secs;
		if (elapsed >= 30) {
			arosExecTimedOut = true;
			logme(L_WARN, "@%ld:%ld AROS exec timeout for %s", server->getSockFd(), channel, xbuffer);
			static const char msg[] = "bebbosshd/AROS: command timeout, sending break\r\n";
			server->channelWrite(channel, msg, sizeof(msg) - 1);
			sendBreak();
		}
	}
#endif
}

void ShellChannel::sendBreak() {
	if (breakPort1 && breakPort1 != port) {
		logme(L_TRACE, "@%ld:%ld break %s with breakPort=%p", server->getSockFd(), channel, getName(), breakPort1);
		logme(L_DEBUG, "@%ld:%ld signal BREAK to %s", server->getSockFd(), channel, getName());
		Signal((struct Task*)breakPort1->mp_SigTask, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F);
	}
	if (breakPort2 && breakPort2 != port) {
		logme(L_TRACE, "@%ld:%ld break %s with breakPort=%p", server->getSockFd(), channel, getName(), breakPort2);
		logme(L_DEBUG, "@%ld:%ld signal BREAK to %s", server->getSockFd(), channel, getName());
		Signal((struct Task*)breakPort2->mp_SigTask, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F);
	}
}

void ShellChannel::prompt() {
	if (!hasPty())
		return;
	char * p = xbuffer;
	*p++ = 0x1b;
	*p++ = '[';
	*p++ = '3';
	*p++ = '2';
	*p++ = 'm';

	// name anhängen
	NameFromLock(dir, p, sizeof(xbuffer) - 12);
	p += strlen(p);

	*p++ = '>';

	*p++ = 0x1b;
	*p++ = '[';
	*p++ = '3';
	*p++ = '9';
	*p++ = 'm';

	*p++ = ' ';
	server->channelWrite(channel, xbuffer, p - xbuffer);
}

static void nqsort(char * p, int length, int ml) {
	char * end = p + length - ml + 1;

	while (p < end) {
		while (*p > ' ' || *p == 0x1b)
			--p;
		while (*p <= ' ' && *p != 0x1b)
			++p;

		char * q = p + ml;
		while (q < end) {
			while (*q > ' ' || *q == 0x1b)
				--q;
			while (*q <= ' ' && *q != 0x1b)
				++q;

			if (strnicmp(p + 5, q + 5, ml) > 0) {
				for (int i = 0; i < ml + 10; ++i) {
					char x = q[i];
					q[i] = p[i];
					p[i] = x;
				}
			}
			q += ml + 10;
		}

		p += ml + 10;
	}
}

void ShellChannel::autocomplete() {
	if (!hasPty())
		return;

	// find start of argument
	char * p = xpos;
	while (p > line && p[-1] > ' ')
		--p;

	// find last colon or slash
	char * colSlash = 0;
	for (char * q = p; q < xend; ++ q) {
		if (*q == '/' || *q == ':')
			colSlash = q;
	}

	BPTR lock;
	if (colSlash) {
		char x = colSlash[0];
		char y = colSlash[1];
		if (x == '/')
			colSlash[0] = 0;
		else
			colSlash[1] = 0;
		lock = Lock(p, SHARED_LOCK);
		colSlash[0] = x;
		colSlash[1] = y;
		p = colSlash + 1;
	} else {
		lock = DupLock(dir);
	}

	if (!lock)
		return;

	// lock is the dir and p the partial name
	D_S(struct FileInfoBlock, fib);
	if (Examine(lock, fib)) {
		char one[110];

		unsigned plen = strlen(p); // the partial length, entered by used
		unsigned clen = plen; 	   // the completion length
		// determine max len
		unsigned ml = 0;
		unsigned count = 0;
		while (ExNext(lock, fib)) {
			if (strnicmp(p, (const char *)fib->fib_FileName, plen) == 0) {
				unsigned sl = strlen((const char *)fib->fib_FileName);
				if (sl > ml)
					ml = sl;

				if (!count++) {
					strcpy(one, (const char *)fib->fib_FileName);
					clen = sl;
				} else {
					for (int i = plen; i < clen; ++i) {
						char a = one[i];
						char b = ((const char *)fib->fib_FileName)[i];
						if (a >= 'A' && a <= 'Z')
							a += 'a' - 'A';
						if (b >= 'A' && b <= 'Z')
							b += 'a' - 'A';
						if (a != b) {
							clen = i;
							break;
						}
					}
				}
			}
		}
		if (clen > plen) {
			handleData(one + plen, clen - plen);
			if (count == 1)
				handleData((char *)" ", 1);
		} else if (count && Examine(lock, fib)) { // print all
			ml += 2;
			unsigned pos = 0;
			logme(L_DEBUG, "cols=%ld, rows=%ld", cols, rows);
			char * q = xbuffer;
			*q++ = '\r';
			*q++ = '\n';
			// loop again
			while (ExNext(lock, fib)) {
				if (strnicmp(p, (const char *)fib->fib_FileName, plen) == 0) {

					*q++ = 0x1b;
					*q++ = '[';
					*q++ = '3';
					if (fib->fib_DirEntryType > 0)
						*q++ = '3';
					else if (fib->fib_Protection & 2)
						*q++ = '1';
					else
						*q++ = '2';
					*q++= 'm';

					// print name
					unsigned sl = strlen((const char *)fib->fib_FileName);
					strcpy(q, (const char *)fib->fib_FileName);
					q += sl;

					*q++ = 0x1b;
					*q++ = '[';
					*q++ = '3';
					*q++ = '1';
					*q++= 'm';

					// fill with spaces
					while (sl++ < ml)
						*q++ = ' ';

					// add lf
					if (pos + ml + ml > cols) {
						*q++ = '\r';
						*q++ = '\n';
						pos = 0;
					} else {
						pos += ml;
					}

					if (q - xbuffer > CHUNKSIZE/2) {
						int l = q - xbuffer;
						nqsort(xbuffer, l, ml - 2);
						server->channelWrite(channel, xbuffer, l);
						q = xbuffer;
					}
				}
			}
			if (pos) {
				*q++ = '\r';
				*q++ = '\n';
			}
			int l = q - xbuffer;
			nqsort(xbuffer, l, ml - 2);
			server->channelWrite(channel, xbuffer, l);
			prompt();
			server->channelWrite(channel, line, xpos - line);
		}
	}

	UnLock(lock);
}

void ShellChannel::cmdCD(char * q) {
	if (0 == strcmp(q, ".."))
		q = (char *)"/";
	else
	if (0 == strcmp(q, "."))
		q = (char *)"";
	if (0 == strcmp(q, "?")) {
		server->channelWrite(channel, "cd <path>\r\n", 11);
	} else {
		// no absolute path, change directory
		logme(L_FINE, "@%ld:%ld cd -> %s", server->getSockFd(), channel, q);
		BPTR old = CurrentDir(dir);
		BPTR newDir = Lock(q, SHARED_LOCK);
		if (old && newDir) {
			CurrentDir(old);
			UnLock(dir);
			dir = newDir;
		} else {
			server->channelWrite(channel, "object not found\r\n", 18);
			if (old) CurrentDir(old);
		}
	}
}

char * ShellChannel::cursorLeft(char * out, int slen) {
	if (!slen)
		return out;
	// move left
	*out++ = 0x1b; // cursor left
	*out++ = '[';
	if (slen > 1) {
		utoa(slen, out, 10);
		out += strlen(out);
	}
	*out++ = 'D';
	return out;
}

char * ShellChannel::cursorRight(char * out, int slen) {
	if (!slen)
		return out;
	// move left
	*out++ = 0x1b; // cursor left
	*out++ = '[';
	if (slen > 1) {
		utoa(slen, out, 10);
		out += strlen(out);
	}
	*out++ = 'C';
	return out;
}

char * ShellChannel::redrawRestOfLine(char * out) {
	int slen = xend - xpos;
	if (0 == slen) {
		*out++ = 0x1b; // erase end of line
		*out++ = '[';
		*out++ = 'K';
		return out;
	}

	*xend = 0;
	logme(L_FINE, "@%ld:%ld redrawRestOfLine %ld %s", server->getSockFd(), channel, slen, xpos);
	memcpy(out, xpos, slen);
	out += slen;
	*out++ = 0x1b; // erase end of line
	*out++ = '[';
	*out++ = 'K';

	return cursorLeft(out, slen);
}

/**
 * returns true if the server stays alive, false otherwise.
 */
int ShellChannel::handleData(char * indata, unsigned len) {
	indata[len] = 0;

	if (running) { // forward data to running program

		// send CTRL c
		if (len == 1 && *indata == 3)
			sendBreak();
		memmove(xpos, indata, len + 1);

		// hack to support the weird argument handling
		// local echo enabled if there was last '?'
		if (localEcho || (pty && *xpos == 0x1b)) {
			char * q = xpos;
			for (;;) {
				q = strchr(q, '\r');
				if (!q)
					break;
				*q = '\n';
			}

			// keep localEcho on?
			if (localEcho) {
				q = strrchr(xpos, '\n');
				if (q)
					localEcho = q > xpos && q[-1] == '?'; // stay on, if '?'
			}

			write(xpos, len);
		}

		xpos += len;
		xend += len;
		if (pending) {
			struct Message * m = pending;
			pending = 0;
			handleMsg(m);
		}
	} else { // handle the data

		if (pty) {
			// handle CTRL+D
			if (xpos == line && indata[0] == 4) {
				handleData((char *)"exit\r", 5);
				return -1;
			}
			// handle completion
			if (len == 1 && indata[0] == '\t') {
				autocomplete();
				return 0;
			}
		}

		// update line indata

		char * out = outbuffer;
		char * out0 = out;
		for (unsigned i = 0; i < len; ++i) {
			if (xpos - line >= CHUNKSIZE)
				continue;

			char c = indata[i];
			logme(L_TRACE, "@%ld:%ld line[%2d]=%02x %c, %p %p", xpos - line, server->getSockFd(), channel, c & 0xff, (c &0xff) >= ' ' ? (c &0xff) : '.', xpos, xend);
			switch (c) {
			case 1: // CTRL+A
			CTRLA:
				out = cursorLeft(out, xpos - line);
				xpos = line;
				break;
			case 5: // CTRL+E
			CTRLE:
				out = cursorRight(out, xend - xpos);
				xpos = xend;
				break;
			case 0: // can this happen?
				c = indata[i] = '\n';
				/* no break */
			case '\n':
			case '\r': { // start the command and keep the rest of the data
				*out++ = c;
				char * q = line;
				while (*q && *q <= ' ')
					++q;
				memcpy(xbuffer, q, xend - q);
				xbuffer[xend - q] = 0;

				if (pty && q == line && *xbuffer)
					history.put(strdup(xbuffer)); // history peforms the free

				// move not handled data to the start of line
				len -= i;
				if (len)
					memmove(line, &indata[i + 1], len); // copy terminating zero

				xpos = xend = line + len - 1;

				logme(L_TRACE, "@%ld:%ld len(cmd)=%ld len(line)=%ld, len=%ld  line:%s", server->getSockFd(), channel, strlen(xbuffer), strlen(line), xpos - line, line);

				write(out0, out - out0);
				return startCommand() ? 0 : -1;
			}
			break;
			case 0x1b: // escape sequence
				if (!pty)
					goto OUT;
				{
					if (i + 1 == len) { // single escape
						out = cursorLeft(out, xpos - line);
						out = redrawRestOfLine(out);
						xpos = xend = line;
						history.toEnd();
						break;
					}

					char * esc = &indata[i];
					char z = 0;
					int ii = i;
					for(i += 2;i < len; ++i) {
						z = indata[i];
						if (z == 7 || (z >= 0x40 && z <= 0x7E))
							break;
					}
					++i;
					ii = i - ii;
					logme(L_TRACE, "@%ld:%ld escape sequence %c", server->getSockFd(), channel, z);

					switch (z) {
					case 'A': // cursor up
					case 'B': // cursor down
					{
						char const * t = z == 'A' ? history.getPrev() : history.getNext();
						if (!t) {
							if (z == 'A')
								break;
							t = "";
						}
						out = cursorLeft(out, xpos - line);
						int l = strlen(t);
						memcpy(out, t, l);
						out += l;
						memcpy(line, t, l);
						xpos = xend = line + l;
						out = redrawRestOfLine(out);
					}
						break;
					case 'C': // cursor right
						if (xpos < xend) {
							// with CTRL?
							if (indata[i - 2] == '5') {
								// find next white space
								char * p = xpos;
								while (p < xend && *p > ' ')
									++p;
								while (p < xend && *p <= ' ')
									++p;
								out = cursorRight(out, p - xpos);
								xpos = p;
							} else {
								++xpos;
								out = cursorRight(out, 1);
							}
						}
						break;
					case 'D': // cursor left
						if (xpos > line) {
							// with CTRL?
							if (indata[i - 2] == '5') {
								// find prev white space
								char * p = xpos;
								while (p > line && p[-1] <= ' ')
									--p;
								while (p > line && p[-1] > ' ')
									--p;
								out = cursorLeft(out, xpos - p);
								xpos = p;
							} else {
								--xpos;
								memcpy(out, esc, ii);
								out += ii;
							}
						}
						break;
					case 'F':
						goto CTRLE;
					case 'H':
						goto CTRLA;
					case '~': // delete
						if (xpos < xend) {
							int slen = xend - xpos + 1;
							memmove(xpos, xpos + 1, slen);
							*--xend = 0;
							out = redrawRestOfLine(out);
						}
						break;
					}
				}
				break;
			case 0x8:
			case 0x7f: // backspace = one left then same as delete
				if (pty)
				{
				if (xpos == line)
					continue;
				int slen = xend - xpos + 1;
				--xpos;
				memmove(xpos, xpos + 1, slen);

				*out++ = 0x1b; // cursor left
				*out++ = '[';
				*out++ = 'D';

				*--xend = 0;
				out = redrawRestOfLine(out);
					break;
				}
				/* no pty! */
				/* no break */
			default:
OUT:
				for (char * s = xend, *t = xend + 1;s > xpos;) {
					*--t = *--s;
				}
				*++xend = 0;
				*xpos++ = c;
				*out++ = c;
				if (pty && xend - xpos) {
					out = redrawRestOfLine(out);
				}
			}
			logme(L_TRACE, "@%ld:%ld line=%s", server->getSockFd(), channel, line);
			dump("out", out0, out - out0);
		}
		if (out != out0)
			write(out0, out - out0);

		if (stopped) {
			server->close();
			return -1;
		}
	}
	return 0;
}

__saveds
void ShellChannel::endProc() {
//	struct Process * process = (struct Process *)FindTask(0);
//	struct CommandLineInterface * cli = (struct CommandLineInterface *)BADDR(process->pr_CLI);
//	printf("%ld\n", cli->cli_ReturnCode); // not used atm
}

#if BEBBOSSH_AROS
void ShellChannel::endArosExecProc(IPTR rc, IPTR data) {
	ShellChannel *sc = (ShellChannel *)data;
	if (!sc)
		return;
	sc->arosExecRc = (LONG)rc;
	sc->done = 1;
	Signal(thisTask, SIGBREAKF_CTRL_F);
}
#endif

__saveds
void ShellChannel::startProc() {
	struct Process * process = (struct Process *)FindTask(0);
	ShellChannel * sc = (ShellChannel *)process->pr_ExitData;
#if BEBBOSSH_AROS
	if (sc->arosExecFileMode) {
		BPTR input = Open("NIL:", MODE_OLDFILE);
		BPTR output = Open(sc->arosExecOutName, MODE_NEWFILE);
		if (output) {
			BPTR oldDir = CurrentDir(sc->dir);
			sc->arosExecRc = SystemTags(sc->xbuffer,
					SYS_Input, input ? input : Input(),
					SYS_Output, output,
					SYS_Error, output,
					SYS_UserShell, (IPTR)TRUE,
					TAG_DONE);
			CurrentDir(oldDir);
			Close(output);
		} else {
			sc->arosExecRc = 20;
		}
		if (input)
			Close(input);
		sc->done = 1;
		Signal(thisTask, SIGBREAKF_CTRL_F);
		return;
	}

	struct FileHandle * i = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, 0);
	struct FileHandle * o = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, 0);
	struct FileHandle * e = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, 0);

	if (i && o && e) {
		i->fh_Flags = 5; // no buffer
		i->fh_Port = 1; // interactive
		i->fh_Type = port;
		i->fh_Pos = -1;
		i->fh_End = -1;
		i->fh_Arg1 = (SIPTR)sc;

		o->fh_Flags = 1; // with buffer
		o->fh_Port = 1; // interactive
		o->fh_Type = port;
		o->fh_Pos = -1;
		o->fh_End = -1;
		o->fh_Arg1 = (SIPTR)sc;

		e->fh_Flags = 1; // with buffer
		e->fh_Port = 1; // interactive
		e->fh_Type = port;
		e->fh_Pos = -1;
		e->fh_End = -1;
		e->fh_Arg1 = (SIPTR)sc;

		SystemTags(sc->xbuffer,
				SYS_Input, MKBADDR(i),
				SYS_Output, MKBADDR(o),
				SYS_Error, MKBADDR(e),
				SYS_UserShell, (IPTR)TRUE,
				NP_StackSize, sc->stackSize,
				TAG_DONE
				);
	}

	if (i)
		FreeDosObject(DOS_FILEHANDLE, i);
	if (o)
		FreeDosObject(DOS_FILEHANDLE, o);
	if (e)
		FreeDosObject(DOS_FILEHANDLE, e);
#elif 1
	struct FileHandle * i = (struct FileHandle *)AllocVec(theInputSize, MEMF_PUBLIC | MEMF_CLEAR);
//	struct FileHandle * o = (struct FileHandle *)AllocVec(theOutputSize, MEMF_PUBLIC | MEMF_CLEAR);
	struct FileHandle * o = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, 0);

	if (i && o) {

		memcpy(i, theInput, theInputSize);
		i->fh_Type = port;
		i->fh_Arg1 = (SIPTR)sc;

		//memcpy(o, theOutput, theOutputSize);
		o->fh_Flags = 1; // with buffer
		o->fh_Port = 1; // interactive
		o->fh_Type = port;
		o->fh_Pos = -1;
		o->fh_End = -1;

		if (readFx) {
			o->fh_Func2 = writeFx;
			o->fh_Func3 = flushFx;
		} else {
			o->fh_Func2 = theOutput->fh_Func2;
			o->fh_Func3 = theOutput->fh_Func3;
		}

		o->fh_Arg1 = (SIPTR)sc;

		SystemTags(sc->xbuffer,
				SYS_Input, MKBADDR(i),
				SYS_Output, MKBADDR(o),
				SYS_UserShell, (IPTR)TRUE,
				NP_StackSize, sc->stackSize,
				NP_ExitCode, (IPTR)endProc,
				TAG_DONE
				);
	}

	if (i)
		FreeVec(i);
	if (o)
		FreeDosObject(DOS_FILEHANDLE, o);

#else

	// freed by SystemTagList
	struct FileHandle * i = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, 0);
	struct FileHandle * o = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, 0);
	if (i && o) {
		i->fh_Flags = 5; // no buffer
		i->fh_Port = 1; // interactive
		i->fh_Type = port;
		i->fh_Func1 = readFx;
		i->fh_Arg1 = (SIPTR)sc;

		o->fh_Flags = 1; // with buffer
		o->fh_Type = port;
		o->fh_Func2 = writeFx;
		o->fh_Func3 = flushFx;
		o->fh_Arg1 = (SIPTR)sc;

		struct TagItem tags[6];
		tags[0].ti_Tag = SYS_Input;
		tags[0].ti_Data = MKBADDR(i);
		tags[1].ti_Tag = SYS_Output;
		tags[1].ti_Data = MKBADDR(o);
		tags[2].ti_Tag = SYS_UserShell;
		tags[2].ti_Data = (IPTR)TRUE;
		tags[3].ti_Tag = NP_StackSize;
		tags[3].ti_Data = sc->stackSize;
		tags[4].ti_Tag = NP_ExitCode;
		tags[4].ti_Data = (IPTR)endProc;
		tags[5].ti_Tag = TAG_DONE;
		SystemTagList(sc->xbuffer, tags);

	}
	//else
	{
		if (i)
			FreeDosObject(DOS_FILEHANDLE, i);
		if (o)
			FreeDosObject(DOS_FILEHANDLE, o);
	}
#endif

	sc->done = 1;
	Signal(thisTask, SIGBREAKF_CTRL_F);
}

bool ShellChannel::startCommand(char const * cmd){
	strncpy(xbuffer, cmd, CHUNKSIZE - 1);
	xbuffer[CHUNKSIZE - 1] = 0;
	return startCommand();
}

bool ShellChannel::drainBufferedInput() {
	unsigned len = xpos - line;
	if (!len)
		return true;

	xend = xpos = line;
	if (len + 1 > inBufferLen) {
		char *newBuffer = (char *)realloc(inBuffer, len + 1);
		if (!newBuffer) {
			logme(L_ERROR, "out of memory for %ld of data", len + 1);
			server->closeChannel(this);
			return false;
		}
		inBuffer = newBuffer;
		inBufferLen = len + 1;
	}
	memcpy(inBuffer, line, len);
	inBuffer[len] = 0;
	return handleData(inBuffer, len) >= 0;
}


extern bool sanitize(char * path);

#if BEBBOSSH_AROS
static bool hasUnsupportedArosShellSyntax(const char *cmd) {
	for (const char *p = cmd; *p; ++p) {
		if (*p == '>' || *p == '<' || *p == '|')
			return true;
	}
	return false;
}

static bool isArosInteractiveOnlyExec(const char *cmd, int keywordLen) {
	if ((keywordLen == 4 && 0 == strnicmp(cmd, "more", 4)) ||
			(keywordLen == 2 && 0 == strnicmp(cmd, "ed", 2)) ||
			(keywordLen == 4 && 0 == strnicmp(cmd, "edit", 4)) ||
			(keywordLen == 6 && 0 == strnicmp(cmd, "memacs", 6)) ||
			(keywordLen == 3 && 0 == strnicmp(cmd, "ask", 3)) ||
			(keywordLen == 5 && 0 == strnicmp(cmd, "shell", 5)) ||
			(keywordLen == 7 && 0 == strnicmp(cmd, "newshell", 7)))
		return true;

	return strstr(cmd, "--telegram-client-console") != 0;
}


static bool isExplicitArosCommandPath(const char *cmd, int keywordLen) {
	for (int i = 0; i < keywordLen; ++i) {
		if (cmd[i] == 58 || cmd[i] == 47)
			return true;
	}
	return false;
}

static bool arosCommandExists(const char *cmd, int keywordLen) {
	char path[512];
	if (keywordLen <= 0)
		return false;
	if (keywordLen >= (int)sizeof(path))
		return false;
	memcpy(path, cmd, keywordLen);
	path[keywordLen] = 0;
	BPTR lock = Lock(path, ACCESS_READ);
	if (!lock)
		return false;
	UnLock(lock);
	return true;
}

bool ShellChannel::finishArosExecImmediate(uint32_t exitStatus) {
	arosExecFileMode = true;
	arosExecTimedOut = false;
	arosExecRc = (LONG)exitStatus;
	arosExecOutName[0] = 0;
	running = true;
	done = 1;
	Signal(thisTask, SIGBREAKF_CTRL_F);
	return true;
}

bool ShellChannel::startArosLoadedExecFile(bool closeAfterCommand) {
	int keywordLen = 0;
	char *argp;
	int argLen = 0;

	while (xbuffer[keywordLen] && xbuffer[keywordLen] > 32)
		++keywordLen;
	if (!isExplicitArosCommandPath(xbuffer, keywordLen))
		return false;
	if (keywordLen <= 0 || keywordLen >= (int)sizeof(arosExecCommandName))
		return false;
	memcpy(arosExecCommandName, xbuffer, keywordLen);
	arosExecCommandName[keywordLen] = 0;

	BPTR seg = LoadSeg(arosExecCommandName);
	if (!seg) {
		char msg[600];
		int nameLen = keywordLen < (int)sizeof(msg) - 21 ? keywordLen : (int)sizeof(msg) - 21;
		memcpy(msg, xbuffer, nameLen);
		memcpy(msg + nameLen, ": object not found\r\n", 20);
		server->channelWrite(channel, msg, nameLen + 20);
		if (closeAfterCommand)
			return finishArosExecImmediate(127);
		prompt();
		return false;
	}

	arosExecFileMode = true;
	arosExecTimedOut = false;
	arosExecRc = 255;
	snprintf(arosExecOutName, sizeof(arosExecOutName), "T:bebbosshd-%lx-%lx.out", (ULONG)server->getSockFd(), (ULONG)channel);
	DeleteFile(arosExecOutName);
	GetSysTime(&arosExecStarted);

	argp = xbuffer + keywordLen;
	while (*argp && *argp <= 32)
		++argp;
	while (*argp && argLen < (int)sizeof(arosExecArgs) - 2)
		arosExecArgs[argLen++] = *argp++;
	arosExecArgs[argLen++] = 10;
	arosExecArgs[argLen] = 0;

	BPTR input = Open("NIL:", MODE_OLDFILE);
	BPTR output = Open(arosExecOutName, MODE_NEWFILE);
	if (!output) {
		if (input)
			Close(input);
		UnLoadSeg(seg);
		server->channelWrite(channel, "bebbosshd/AROS: cannot create command output file\r\n", 52);
		if (closeAfterCommand)
			server->closeChannel(this, 20);
		else
			prompt();
		return false;
	}

	struct TagItem tags[] = {
			{ NP_Seglist, (IPTR)seg },
			{ NP_FreeSeglist, (IPTR)TRUE },
			{ NP_Cli, (IPTR)TRUE },
			{ NP_Arguments, (IPTR)arosExecArgs },
			{ NP_Input, (IPTR)input },
			{ NP_Output, (IPTR)output },
			{ NP_Error, (IPTR)output },
			{ NP_CloseInput, (IPTR)TRUE },
			{ NP_CloseOutput, (IPTR)TRUE },
			{ NP_CloseError, (IPTR)FALSE },
			{ NP_StackSize, stackSize },
			{ NP_Name, (IPTR)arosExecCommandName },
			{ NP_CommandName, (IPTR)arosExecCommandName },
			{ NP_CurrentDir, (IPTR)DupLock(dir) },
			{ NP_ExitCode, (IPTR)ShellChannel::endArosExecProc },
			{ NP_ExitData, (IPTR)this },
			{ TAG_DONE, 0 }
	};

	running = true;
	if (!CreateNewProcTagList(tags)) {
		running = false;
		Close(input);
		Close(output);
		UnLoadSeg(seg);
		if (closeAfterCommand)
			server->closeChannel(this, 20);
		return false;
	}
	return true;
}

bool ShellChannel::startArosExecFile(bool closeAfterCommand) {
#if defined(BEBBOSSH_AROS_MINCRT)
	int keywordLen = 0;
	while (xbuffer[keywordLen] && xbuffer[keywordLen] > 32)
		++keywordLen;
	if (isExplicitArosCommandPath(xbuffer, keywordLen))
		return startArosLoadedExecFile(closeAfterCommand);
#endif
	arosExecFileMode = true;
	(void)closeAfterCommand;
	arosExecTimedOut = false;
	arosExecRc = 255;
	snprintf(arosExecOutName, sizeof(arosExecOutName), "T:bebbosshd-%lx-%lx.out",
			(ULONG)server->getSockFd(), (ULONG)channel);
	DeleteFile(arosExecOutName);
	GetSysTime(&arosExecStarted);

	logme(L_DEBUG, "@%ld:%ld starting AROS exec task %s with cmd `%s`", server->getSockFd(), channel, server->name, xbuffer);
	running = true;
	struct TagItem tags[] = {
			{ NP_Entry, (IPTR)startProc },
			{ NP_StackSize, stackSize },
			{ NP_Cli, 1 },
			{ NP_Name, (IPTR)server->name },
			{ NP_CurrentDir, (IPTR)DupLock(dir) },
			{ NP_ExitData, (IPTR)this },
			{ TAG_DONE, 0 }
	};
	CreateNewProcTagList(tags);
	return true;
}

bool ShellChannel::runArosExec(bool closeAfterCommand) {
	char outName[96];
	snprintf(outName, sizeof(outName), "T:bebbosshd-%lx-%lx.out",
			(ULONG)server->getSockFd(), (ULONG)channel);

	BPTR input = Open("NIL:", MODE_OLDFILE);
	BPTR output = Open(outName, MODE_NEWFILE);
	if (!output) {
		static const char msg[] = "bebbosshd/AROS: cannot create command output file\r\n";
		server->channelWrite(channel, msg, sizeof(msg) - 1);
		if (input)
			Close(input);
		if (closeAfterCommand) {
			server->closeChannel(this, 20);
			return false;
		}

		prompt();
		return true;
	}

	BPTR oldDir = CurrentDir(dir);
	LONG rc = SystemTags(xbuffer,
			SYS_Input, input ? input : Input(),
			SYS_Output, output,
			SYS_Error, output,
			SYS_UserShell, (IPTR)TRUE,
			TAG_DONE);
	CurrentDir(oldDir);

	if (input)
		Close(input);
	Close(output);

	output = Open(outName, MODE_OLDFILE);
	if (output) {
		char buf[2048];
		for (;;) {
			LONG got = Read(output, buf, sizeof(buf));
			if (got <= 0)
				break;
			server->channelWrite(channel, buf, got);
		}
		Close(output);
	}
	DeleteFile(outName);

	if (rc && !closeAfterCommand) {
		char msg[80];
		int len = snprintf(msg, sizeof(msg), "bebbosshd/AROS: command returned %ld\r\n", rc);
		server->channelWrite(channel, msg, len);
	}

	if (closeAfterCommand) {
		uint32_t exitStatus = (rc < 0 || rc > 255) ? 255 : (uint32_t)rc;
		server->closeChannel(this, exitStatus);
		return false;
	}

	prompt();
	return drainBufferedInput();
}
#endif

bool ShellChannel::startCommand(){
	char * c = xbuffer;
	while (*c > ' ')
		++c;
	int keywordLen = c - xbuffer;
	if (0 == keywordLen) {
		prompt();
		return drainBufferedInput();
	}

	char tc = *c;
	*c = 0;
	if (!sanitize(xbuffer)) {
		char * t = xbuffer + strlen(xbuffer) + 1;
		int len = snprintf(t, 512, "%s: invalid command\r\n", xbuffer);
		server->channelWrite(channel, t, len);
		if (hasExec()) {
			server->closeChannel(this, 127);
			return false;
		}
		prompt();
		return drainBufferedInput();
	}

	// insert spaces into sanitized command
	char * t = xbuffer + strlen(xbuffer);
	while (t < c)
		*t++ = ' ';
	*c = tc;

	// advance to parameter
	char * q = c;
	while (*q && *q <= ' ')
		++q;

	// end of first parameter
	char * p = q;
	while (*p > ' ')
		++p;

	// handle exit - ignore params
	if (keywordLen == 4 && 0 == strnicmp(xbuffer, "exit", 4)) {
		server->closeChannel(this);
		return false;
	}

	// handle cd with at least one param
	if (keywordLen == 2 && 0 == strnicmp(xbuffer, "cd", 2) && p > q) {
		*p = 0;
		cmdCD(q);
		prompt();
		return drainBufferedInput();
	}

	// handle stack with at least one param
	if (keywordLen == 5 && 0 == strnicmp(xbuffer, "stack", 5) && p > q) {
		*p = 0;
		stackSize = strtoul(q, 0, 10);
		if (stackSize < 4096)
			stackSize = 4096;
		prompt();
		return drainBufferedInput();
	}

	localEcho = xbuffer[strlen(xbuffer) - 1] == '?';


#if BEBBOSSH_AROS
	if (!hasExec() && keywordLen == 3 && 0 == strnicmp(xbuffer, "dir", 3)) {
		char *args = xbuffer + 3;
		while (*args && *args <= ' ')
			++args;
		if (!*args) {
			strcpy(xbuffer, "list lformat %N");
		} else if (!strstr(args, "lformat") && !strstr(args, "LFORMAT")) {
			char dirArgs[CHUNKSIZE];
			strncpy(dirArgs, args, sizeof(dirArgs) - 1);
			dirArgs[sizeof(dirArgs) - 1] = 0;
			snprintf(xbuffer, CHUNKSIZE, "list %s lformat %%N", dirArgs);
		}
	}

	if (hasExec() && !hasPty() && isExplicitArosCommandPath(xbuffer, keywordLen) && !arosCommandExists(xbuffer, keywordLen)) {
		char msg[600];
		int nameLen = keywordLen < (int)sizeof(msg) - 21 ? keywordLen : (int)sizeof(msg) - 21;
		memcpy(msg, xbuffer, nameLen);
		memcpy(msg + nameLen, ": object not found\r\n", 20);
		server->channelWrite(channel, msg, nameLen + 20);
		return finishArosExecImmediate(127);
	}

	if (hasUnsupportedArosShellSyntax(xbuffer)) {
		static const char msg[] = "bebbosshd/AROS: shell redirection and pipes are not supported yet\r\n";
		server->channelWrite(channel, msg, sizeof(msg) - 1);
		if (hasExec()) {
			return finishArosExecImmediate(2);
		}
		prompt();
		return drainBufferedInput();
	}

	if (hasExec() && !hasPty() && isArosInteractiveOnlyExec(xbuffer, keywordLen)) {
		static const char msg[] = "bebbosshd/AROS: interactive command is not supported by the minimal AROS backend yet\r\n";
		server->channelWrite(channel, msg, sizeof(msg) - 1);
		return finishArosExecImmediate(2);
	}

	if (hasExec() && hasPty() && isArosInteractiveOnlyExec(xbuffer, keywordLen)) {
		static const char msg[] = "bebbosshd/AROS: interactive command is not supported by the minimal AROS backend yet\r\n";
		server->channelWrite(channel, msg, sizeof(msg) - 1);
		return finishArosExecImmediate(2);
	}

	if (hasExec())
		return startArosExecFile(true);

	if (isArosInteractiveOnlyExec(xbuffer, keywordLen)) {
		static const char msg[] = "bebbosshd/AROS: interactive command is not supported by the minimal AROS backend yet\r\n";
		server->channelWrite(channel, msg, sizeof(msg) - 1);
		prompt();
		return drainBufferedInput();
	}

	return runArosExec(false);
#endif

	logme(L_DEBUG, "@%ld:%ld starting task %s with cmd `%s`", server->getSockFd(), channel, server->name, xbuffer);
	running = true;
	struct TagItem tags[] = {
			{ NP_Entry, (IPTR)startProc },
			{ NP_StackSize, stackSize },
			{ NP_Cli, 1 },
			{ NP_Name, (IPTR)server->name },
			{ NP_CurrentDir, (IPTR)DupLock(dir) },
			{ NP_ExitData, (IPTR)this },
			{ TAG_DONE, 0 }
	};
	CreateNewProcTagList(tags);
	return true;
}

bool ShellChannel::endCommand(){
	logme(L_DEBUG, "@%ld:%ld ended task %s with cmd `%s`", server->getSockFd(), channel, server->name, xbuffer);
	running = 0;
	breakPort1 = breakPort2 = 0;
	done = exec;
#if BEBBOSSH_AROS
	if (arosExecFileMode) {
		if (arosExecOutName[0]) {
			BPTR output = Open(arosExecOutName, MODE_OLDFILE);
			if (output) {
				char buf[2048];
				for (;;) {
					LONG got = Read(output, buf, sizeof(buf));
					if (got <= 0)
						break;
					server->channelWrite(channel, buf, got);
				}
				Close(output);
			}
			DeleteFile(arosExecOutName);
			arosExecOutName[0] = 0;
		}
		if (arosExecTimedOut && arosExecRc == 0)
			arosExecRc = 124;
		uint32_t exitStatus = (arosExecRc < 0 || arosExecRc > 255) ? 255 : (uint32_t)arosExecRc;
		server->closeChannel(this, exitStatus);
		return false;
	}
#endif
	if (done) {
		server->closeChannel(this);
		return false;
	}

	prompt();

	// apply unused data
	unsigned len = xpos - line;
	xend = xpos = line;

	if (len + 1 > inBufferLen) {
		inBuffer = (char *)realloc(inBuffer, len + 1);
		if (!inBuffer) {
			logme(L_ERROR, "out of memory for %ld of data", len + 1);
			server->closeChannel(this);
			return false;
		}
		inBufferLen = len + 1;
	}
	memcpy(inBuffer, line, len);
	inBuffer[len] = 0;

	return handleData(inBuffer, len);
}
#else
// linux

#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>       // declares openpty()
#endif
#include <utmp.h>      // for struct utmp if needed
#include <termios.h>   // for struct termios
#include <sys/ioctl.h> // for ioctl, TIOCSCTTY
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#ifdef __APPLE__
extern char **environ;
static int clearenv(void) { environ[0] = 0; return 0; }
#endif


// helper to dump a file to stdout if it exists
static void show_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            write(STDOUT_FILENO, buf, n);
        }
        close(fd);
    }
}

bool ShellChannel::startCommand(char const * cmd){
    int slave;

    const char *username = server->getUser();
    struct passwd *pw = getpwnam(username);
    if (!pw)
    	return false;

    // make a writable copy of cmd
    char *copy = strdup(cmd);
    if (!copy) return false;

    // argv array (fixed size for simplicity)
    char *argv[64];
    int argc = 0;

    // tokenize on whitespace
    char *token = strtok(copy, " \t\r\n");
    while (token && argc < 63) {
        argv[argc++] = token;
        token = strtok(NULL, " \t\r\n");
    }
    argv[argc] = NULL;

    if (argc == 0) {
        free(copy);
        return false;
    }

    const char *program = argv[0];

    // If this is a shell, mark it as a login shell
    if (strcmp(program, "bash") == 0 ||
        strcmp(program, "/bin/bash") == 0 ||
        strcmp(program, "sh") == 0 ||
        strcmp(program, "/bin/sh") == 0) {
        argv[0] = concat("-", argv[0], 0);   // prepend dash
    } else {
    	argv[0] = strdup(argv[0]);
    }

    if (openpty(&master, &slave, NULL, NULL, NULL) == -1) {
        return false;
    }

    pid = fork();
    if (pid < 0) {
        close(master);
        close(slave);
        return false;
    }

	if (pid == 0) {
		// child
		close(master);

		// Optionally set PTY size before attaching
		struct winsize ws = {24, 80, 0, 0};
		ioctl(slave, TIOCSWINSZ, &ws);

		// Make slave the controlling terminal and hook up stdin/out/err
		if (login_tty(slave) < 0) {
			perror("login_tty");
			_exit(1);
		}

		// --- switch to user uid/gid ---
		if (initgroups(pw->pw_name, pw->pw_gid) == 0) {
			setgid(pw->pw_gid);
		}
		setuid(pw->pw_uid);

	    // --- display MOTD ---
	    show_file("/etc/motd");

		clearenv();

		// set environment variables
		setenv("HOME", pw->pw_dir, 1);
		setenv("USER", pw->pw_name, 1);
		setenv("LOGNAME", pw->pw_name, 1);
		setenv("SHELL", pw->pw_shell, 1);
		setenv("TMPDIR", "/tmp", 1);

		setenv("LINES", "24", 1);
		setenv("COLUMNS", "80", 1);

		// TERM comes from the client side; set a default if missing
		if (!getenv("TERM")) {
			setenv("TERM", "xterm-256color", 1);
		}

		// set working directory to user's home
		if (chdir(pw->pw_dir) == 0) {
			setenv("PWD", pw->pw_dir, 1);
		}

		execvp(program, argv);
		_exit(127);
	}

    // parent
    close(slave);
    free(argv[0]);
    return true;
}

void ShellChannel::prompt() {
    const char *username = server->getUser();
    const char *shell = "/bin/sh"; // fallback

    if (username && username[0] != '\0') {
        struct passwd *pw = getpwnam(username);
        if (pw && pw->pw_shell && pw->pw_shell[0] != '\0') {
            shell = pw->pw_shell;
        }
    }

    startCommand(shell);
}

static int waitpid_timeout(pid_t pid, int *status, int timeout_ms) {
    int elapsed = 0;
    const int step = 50; // check every 50ms
    while (elapsed < timeout_ms) {
        pid_t r = waitpid(pid, status, WNOHANG);
        if (r == pid) {
            // child exited
            return 1;
        } else if (r == 0) {
            // still running
            usleep(step * 1000);
            elapsed += step;
            continue;
        } else {
            // error
            return -1;
        }
    }
    // timeout reached, child still running
    return 0;
}

void ShellChannel::abort() {
    if (pid) {
        kill(pid, SIGTERM);

        int status;
        int r = waitpid_timeout(pid, &status, 500);
        if (r == 1) {
            // child exited cleanly
        } else if (r == 0) {
            // timeout: child still running, you may escalate (SIGKILL)
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0); // reap after kill
        } else {
            // error case
        }

        pid = 0;
    }
}

void ShellChannel::sendBreak() {
	if (pid) {
		kill(pid, SIGINT);
		pid = 0;
	}
}
void ShellChannel::checkTimeout(timeval*) {

}

int ShellChannel::handleData(char* buffer, unsigned sz) {
    size_t off = 0;
    while (off < sz) {
        ssize_t n = write(master, buffer + off, sz - off);
        if (n > 0) {
            off += n;
        } else if (n < 0 && errno == EINTR) {
            continue; // retry
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // partial write, return how many bytes are left
            return sz - off;
        } else {
            // fatal error
            return -1;
        }
    }
    // all bytes written
    return 0;
}


bool ShellChannel::endCommand() {
	return false;

}

bool ShellChannel::isPending() const {
	if (pid <= 0) return false;
	return (kill(pid, 0) == 0 || errno == EPERM);
}

int ShellChannel::handleRead() {
	char * out = &server->outdata[14];
	int n = read(master, out, CHUNKSIZE);
	if (n > 0) {
		server->channelWrite(channel, out, n);
	} else if (n < 0) {
		abort();
	}
	return n;
}

#endif
