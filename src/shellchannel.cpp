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
#include <amistdio.h>

#include <dos/dosextens.h>
#include <dos/dostags.h>
#include <proto/dos.h>
#include <proto/exec.h>
#include <proto/socket.h>
#include <proto/timer.h>

#include <log.h>
#include <sshsession.h>
#include <test.h>

#include "channel.h"
#include "shellchannel.h"

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

static inline struct DosPacket * getDosPacket (struct Message * m){
	return (struct DosPacket*) m->mn_Node.ln_Name;
}

ShellChannel::ShellChannel(SshSession * server, uint32_t channel, ChannelType type)
: Channel(server, channel, type),
		pty(false), shell(false), exec(false), localEcho(false),
		stackSize(::stackSize),
		running(false), done(false),
		breakPort1(0), breakPort2(0), pending(0), waiting(0),
		xpos(line), xend(line),
		inBufferLen(0), inBuffer(0),
		history(32), rows(0), cols(0)
{
	*xend = 0;
	if (homeDir)
		dir = Lock(homeDir, SHARED_LOCK);
	if (!dir)
		dir = Lock("RAM:", SHARED_LOCK);
	logme(L_DEBUG, "@%ld:%ld opening shell channel", server->getSockFd(), channel);
}


ShellChannel::~ShellChannel() {
	free(inBuffer);
	if (dir)
		UnLock(dir);
	logme(L_DEBUG, "@%ld:%ld terminating shell channel", server->getSockFd(), channel);
}

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
	int toRead = (toRead > avail) ? avail : toReadIn;

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
			if (strnicmp(p, fib->fib_FileName, plen) == 0) {
				unsigned sl = strlen(fib->fib_FileName);
				if (sl > ml)
					ml = sl;

				if (!count++) {
					strcpy(one, fib->fib_FileName);
					clen = sl;
				} else {
					for (int i = plen; i < clen; ++i) {
						char a = one[i];
						char b = fib->fib_FileName[i];
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
				if (strnicmp(p, fib->fib_FileName, plen) == 0) {

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
					unsigned sl = strlen(fib->fib_FileName);
					strcpy(q, fib->fib_FileName);
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

__saveds
void ShellChannel::startProc() {
	struct Process * process = (struct Process *)FindTask(0);
	ShellChannel * sc = (ShellChannel *)process->pr_ExitData;
#if 1
	struct FileHandle * i = (struct FileHandle *)AllocVec(theInputSize, MEMF_PUBLIC | MEMF_CLEAR);
//	struct FileHandle * o = (struct FileHandle *)AllocVec(theOutputSize, MEMF_PUBLIC | MEMF_CLEAR);
	struct FileHandle * o = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, 0);

	if (i && o) {

		memcpy(i, theInput, theInputSize);
		i->fh_Type = port;
		i->fh_Arg1 = (LONG)sc;

		//memcpy(o, theOutput, theOutputSize);
		o->fh_Link = (struct Message *)1; // with buffer
		o->fh_Port = (struct MsgPort *)1; // interactive
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

		o->fh_Arg1 = (LONG)sc;

		SystemTags(sc->xbuffer,
				SYS_Input, MKBADDR(i),
				SYS_Output, MKBADDR(o),
				SYS_UserShell, (ULONG) TRUE,
				NP_StackSize, sc->stackSize,
				NP_ExitCode, (ULONG) endProc,
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
		i->fh_Link = (struct Message *)5; // no buffer
		i->fh_Port = (struct MsgPort *)1; // interactive
		i->fh_Type = port;
		i->fh_Func1 = readFx;
		i->fh_Arg1 = (LONG)sc;

		o->fh_Link = (struct Message *)1; // with buffer
		o->fh_Type = port;
		o->fh_Func2 = writeFx;
		o->fh_Func3 = flushFx;
		o->fh_Arg1 = (LONG)sc;

		struct TagItem tags[6];
		tags[0].ti_Tag = SYS_Input;
		tags[0].ti_Data = MKBADDR(i);
		tags[1].ti_Tag = SYS_Output;
		tags[1].ti_Data = MKBADDR(o);
		tags[2].ti_Tag = SYS_UserShell;
		tags[2].ti_Data = (ULONG)TRUE;
		tags[3].ti_Tag = NP_StackSize;
		tags[3].ti_Data = sc->stackSize;
		tags[4].ti_Tag = NP_ExitCode;
		tags[4].ti_Data = (ULONG)endProc;
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
	return startCommand();
}

extern bool sanitize(char * path);

bool ShellChannel::startCommand(){
	char * c = xbuffer;
	while (*c > ' ')
		++c;
	int keywordLen = c - xbuffer;
	if (0 == keywordLen) {
		prompt();
		return true;
	}

	char tc = *c;
	*c = 0;
	if (!sanitize(xbuffer)) {
		char * t = xbuffer + strlen(xbuffer) + 1;
		int len = snprintf(t, 512, "%s: invalid command\r\n", xbuffer);
		server->channelWrite(channel, t, len);
		prompt();
		return true;
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
		return true;
	}

	// handle stack with at least one param
	if (keywordLen == 5 && 0 == strnicmp(xbuffer, "stack", 5) && p > q) {
		*p = 0;
		stackSize = strtoul(q, 0, 10);
		if (stackSize < 4096)
			stackSize = 4096;
		prompt();
		return true;
	}

	localEcho = xbuffer[strlen(xbuffer) - 1] == '?';


	logme(L_DEBUG, "@%ld:%ld starting task %s with cmd `%s`", server->getSockFd(), channel, server->name, xbuffer);
	running = true;
	ULONG tags[] = { NP_Entry, (ULONG )startProc,
			NP_StackSize, stackSize,
			NP_Cli, 1,
			NP_Name, (ULONG )server->name,
			NP_CurrentDir, (ULONG)DupLock(dir),
			NP_ExitData, (ULONG)this,
			TAG_END};
	CreateNewProcTagList((struct TagItem *)tags);
	return true;
}

bool ShellChannel::endCommand(){
	logme(L_DEBUG, "@%ld:%ld ended task %s with cmd `%s`", server->getSockFd(), channel, server->name, xbuffer);
	running = 0;
	breakPort1 = breakPort2 = 0;
	done = exec;
	if (done) {
		server->closeChannel(this);
		return false;
	}

	prompt();

	// apply unused data
	unsigned len = xpos - line;
	xend = xpos = line;

	if (len > inBufferLen) {
		inBuffer = (char *)realloc(inBuffer, len);
		if (!inBuffer) {
			logme(L_ERROR, "out of memory for %ld of data", len);
			server->closeChannel(this);
			return false;
		}
	}
	memcpy(inBuffer, line, len);

	return handleData(inBuffer, len);
}

