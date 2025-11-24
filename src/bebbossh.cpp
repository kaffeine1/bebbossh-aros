/*
 * bebbossh - interactive SSH client
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
 * Project: bebbossh - SSH client for Amiga
 * Purpose: Provide interactive terminal sessions over SSH2
 *
 * Features:
 *  - PTY negotiation and terminal emulation
 *  - Console size detection and mouse event handling
 *  - Command execution and shell support
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Optimized for AmigaOS Intuition and bsdsocket.library.
 *
 * Author's intent:
 *  Deliver a usable SSH client experience on classic Amiga systems.
 * ----------------------------------------------------------------------
 */
#include <stdint.h>

#include <amistdio.h>
#include <stdlib.h>
#include <signal.h>

#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>

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

#include <log.h>
#include <stack.h>
#include <test.h>

#include "revision.h"
#include "keyboard.h"
#include "ssh.h"
#include "client.h"
#include "clientchannel.h"

//#define LOG_KEYS
#if defined LOG_KEYS
BPTR keylog;
#endif

extern char hostnameSet, portSet, usernameSet, consoleSet, termSet, keyfileSet, loglevelSet;
extern char const * configFile;
extern char const * encOrder;
extern char const * userOrder;

static bool pty = true;
static bool mouseOn = false;

static char *myWindowTitle;
static char *command;

static uint8_t CHANNEL_PTY[17] = {
SSH_MSG_CHANNEL_REQUEST, 0x00, 0x00, 0x00, 0x00, // channel 0
		0x00, 0x00, 0x00, 0x07, 'p', 't', 'y', '-', 'r', 'e', 'q', 0x01, // want reply
		};
static const char *TERM = "xterm-amiga";
static uint32_t numCols;
static uint32_t numRows;
static uint8_t TERMCAPS[43] = { 0x00, 0x00, 0x00, 0x0, // terminal width, pixels
		0x00, 0x00, 0x00, 0x0, // terminal height, pixels
		0x00, 0x00, 0x00, 6 * 5 + 1, // length of the options
		0x01, 0x00, 0x00, 0x00, 'C' - 'A' + 1, // VINTR -> CTRL+C - does it work?

		// 02 -> 1c = sigquit

		0x03, 0x00, 0x00, 0x00, 0x08, // VERASE -> Backspace
		0x05, 0x00, 0x00, 0x00, 'D' - 'A' + 1, // VEOF
		0x08, 0x00, 0x00, 0x00, 'Q' - 'A' + 1, 0x09, 0x00, 0x00, 0x00, 'S' - 'A' + 1, 0x3B, 0x00, 0x00, 0x00, 0x01, // IEXTEN
		0x00 // end of options
		};

static bool getConsoleSize();
static bool sendNewPty() {
	getConsoleSize();
	uint8_t *p = buffer + 5;
	memcpy(p, CHANNEL_PTY, sizeof(CHANNEL_PTY));
	p += sizeof(CHANNEL_PTY);

	putString(p, TERM);

	putInt32(p, numCols);
	putInt32(p, numRows);

	memcpy(p, TERMCAPS, sizeof(TERMCAPS));
	int len = p - (buffer + 5) + sizeof(TERMCAPS);

	return sendEncrypted(buffer + 5, len);
}

static uint8_t EXEC[14] = {
SSH_MSG_CHANNEL_REQUEST, 0x00, 0x00, 0x00, 0x00, // channel 0
		0x00, 0x00, 0x00, 0x04, 'e', 'x', 'e', 'c', 0x01 };

static uint8_t SHELL[15] = {
SSH_MSG_CHANNEL_REQUEST, 0x00, 0x00, 0x00, 0x00, // channel 0
		0x00, 0x00, 0x00, 0x05, 's', 'h', 'e', 'l', 'l', 0x01 };

class ConsoleChannel: public ClientChannel {
	bool pty;
	char const *command;
public:
	inline ConsoleChannel(bool pty_, char const *command_) :
			ClientChannel(clientChannels.getFreeIndex()), pty(pty_), command(command_) {
	}
	bool start();
	virtual int processChannelData(void *data, int len);
};

int ConsoleChannel::processChannelData(void *data, int length) {
	char *c = (char*) data;
	if (escape) {
		// enable da mouse - can remain there, doesn't disturb
		if (c[0] == 0x1b && c[1] == '[') {
			char *x1006 = strstr((char*) c, "[?1006");
			if (x1006)
				mouseOn = x1006[6] == 'h';
		}

		// handle title somewhere...
		char *title;
		while ((title = strstr((char*) c, "\x1b]0;"))) {
			unsigned l = title - (char*) c;
			if (l) {
				fwrite(c, l, 1, stdout);
				length -= l;
			}

			title += 4;
			char *end = strchr(title, '\7');
			if (!end)
				continue;

			*end++ = 0;
			length -= end - title + 4;
			if (theWindow) {
				free(myWindowTitle);
				myWindowTitle = strdup(title);
				SetWindowTitles(theWindow, myWindowTitle, 0);
			}
			c = end;
		}
	}
	if (length) {
		fwrite(c, length, 1, stdout);
	}
	return 0;
}

bool ConsoleChannel::start() {
	// open new channel
	if (pty) {
		if (!sendNewPty())
			return false;
		if (!receiveEncryptedPacket())
			return false;

		uint8_t *p = buffer + 5;
		if (*p++ != SSH_MSG_CHANNEL_SUCCESS)
			return false;

	}
	remoteChannelNo = 0;

	if (command) {
		uint8_t *b5 = buffer + 5;
		uint8_t *p = b5;
		memcpy(p, EXEC, sizeof(EXEC));
		p += sizeof(EXEC);

		putString(p, command);

		if (!sendEncrypted(b5, p - b5))
			return false;
	} else {
		// open the shell
		if (!sendEncrypted(SHELL, sizeof(SHELL)))
			return false;
	}
	for (;;) {
		if (!receiveEncryptedPacket())
			return false;
		if (buffer[5] == SSH_MSG_CHANNEL_FAILURE)
			return false;
		if (buffer[5] == SSH_MSG_CHANNEL_SUCCESS)
			break;
	}

	if (stdoutBptr) {
		Write(stdoutBptr, "\x1b[2;11;12{", 10); // start events mouse, close, resize
	}
	return true;
}

static uint8_t RESIZE[23] = {
SSH_MSG_CHANNEL_REQUEST, 0, 0, 0, 0, // recipient channel
		0, 0, 0, 13, 'w', 'i', 'n', 'd', 'o', 'w', '-', 'c', 'h', 'a', 'n', 'g', 'e', 0, //   FALSE
		};

static bool sendWindowResize() {
	uint8_t *b5 = buffer + 5;
	memcpy(b5, RESIZE, sizeof(RESIZE));
	uint8_t *p = b5 + sizeof(RESIZE);
	putInt32(p, numCols);
	putInt32(p, numRows);
	putInt32(p, 0);
	putInt32(p, 0);

	return sendEncrypted(b5, p - b5);
}

static uint8_t* makeMouseClick(uint8_t *c) {
	unsigned x = -1;
	unsigned y = 0;
	// 	[2;0;104;49152;0;0;1456263484;838846|
	char *t = strchr((char*) c + 4, ';'); // t = ;104;49152;0;0;1456263484;838846|
	char *sflags = t + 1; // flags = 104;49152;0;0;1456263484;838846|
	if (t)
		t = strchr((char*) sflags, ';'); // t = ;49152;0;0;1456263484;838846|
	if (t) {
		*t = 0;
		t = strchr((char*) t + 1, ';'); // t = ;0;0;1456263484;838846|
	}
	if (t) {
		char *sx = t + 1; // // sx = 0;0;1456263484;838846|
		t = strchr((char*) sx, ';'); // t = ;0;1456263484;838846|
		if (t) {
			*t++ = 0;
			char *sy = t; // s = 0;1456263484;838846|
			char *t = strchr((char*) sy, ';'); // ;1456263484;838846|
			if (t) {
				*t = 0;
				x = atoi(sx);
				y = atoi(sy);
				if (!(x | y)) { // 0, 0 -> read from window
					static unsigned dx, dy;
					theWindow = IntuitionBase->ActiveWindow;
					if (theWindow) {
						struct TextFont *f = theWindow->RPort->Font;
						dx = f->tf_XSize;
						dy = f->tf_YSize;
					}
					x = 1 + theWindow->GZZMouseX / dx;
					y = 1 + theWindow->GZZMouseY / dy;
				}
			}
		}
	}
	// x,y not calculated -> suppress
	if (x < 0)
		return 0;

	unsigned flags = atoi(sflags);

	// replace input with mouse message
	uint8_t *p = c + 2; // after escape
	*p++ = '<';
	*p++ = '0'; // only LMB supported for now
	*p++ = ';';
	utoa(x, (char*) p, 10);
	p += strlen((char*) p);
	*p++ = ';';
	utoa(y, (char*) p, 10);
	p += strlen((char*) p);
	// check flag
	*p++ = (flags & 128) ? 'm' : 'M';
	return p;
}

static bool getConsoleSize() {
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
		numRows = numRows * 10;
		numRows += *q - '0';
	}
	++q;
	numCols = 0;
	for (; q < p; ++q) {
		if (*q == ' ')
			break;
		numCols = numCols * 10;
		numCols += *q - '0';
	}
	return true;
}

void handleKeyboard() {
	uint8_t *b5 = buffer + 5;
	uint8_t *c = b5 + 9; // chars

	uint8_t *p = c;
	if (!stdoutBptr) {
		int sz = 512;

		struct FileHandle * fh = (struct FileHandle *)BADDR(stdinBptr);
		if (fh->fh_Type) { // fix for NIL:
			D_S(struct FileInfoBlock, fib);
			if (ExamineFH(stdinBptr, fib))
				sz = fib->fib_Size;
			else
				SetMode(stdinBptr, 1);

			if (!sz)
				return;
		}

		int n = Read(stdinBptr, p, sz);
		if (n <= 0)
			return;
		p += n;
	} else if (WaitForChar(stdinBptr, 1) == DOSTRUE) {
		Read(stdinBptr, p, 1);
#if defined LOG_KEYS
		fprintf(keylog, "read1=%02lx ", *p);
#endif
		if (escape) {
			if (*p == 0x9b) {
				*p++ = 0x1b;
				*p++ = 0x5b;
				while (WaitForChar(stdinBptr, 10) == DOSTRUE) {
					if (0 == Read(stdinBptr, p, 1))
						break;
					++p;
				}

#if defined LOG_KEYS
			fprintf(keylog, "\nread2");
			for (signed i = 0; i < p - c; ++i)
				fprintf(keylog, "%02lx ", c[i]);
			fprintf(keylog, "\t");
			for (signed i = 0; i < p - c; ++i)
				fprintf(keylog, "%c", c[i]);
			fprintf(keylog, "\t");
			fflush(keylog);
			fputs("A1", keylog); fflush(keylog);
	#endif

				// remove repetition marker
				while (p - c >= 3 && p[-2] == 0x9b && p[-1] == p[-3]) {
					p -= 2;
				}
				while (p - c >= 5 && p[-3] == 0x9b && p[-1] == p[-4] && p[-2] == p[-5]) {
					p -= 3;
				}

				// convert SHIFT LEFT / SHIFT RIGHT
				if (p - c == 4 && p[-2] == ' ') {
					uint8_t last = p[-1];
					p -= 2;
					*p++ = '1';
					*p++ = ';';
					*p++ = '2';
					*p++ = last == 'A' ? 'D' : 'C';
				} // add qualifiers
				else if (p - c == 3) {
					uint8_t last = p[-1];
					// cursor keys
					if (last >= 'A' && last <= 'D') {
						uint32_t kq = getKeyboardQualifiers();
						if (kq) {
							--p;
							*p++ = 0x31;
							*p++ = 0x3b;
							*p++ = 0x31 + ((kq & (LSHIFT | RSHIFT)) ? 1 : 0) + ((kq & ALT) ? 2 : 0) + ((kq & CTRL) ? 4 : 0);
							*p++ = last;
						}
					}
				} else if (strncmp((char*) c, "\x1b[11;", 5) == 0) { // close gadget
					stopped = true;
					return;
				} else if (strncmp((char*) c, "\x1b[2;", 4) == 0) { // mouse click
					if (!mouseOn)
						return;
					p = makeMouseClick(c);
					if (!p)
						return;
				} else if (strncmp((char*) c, "\x1b[12;", 5) == 0) { // check for window size message
					if (getConsoleSize() && !sendWindowResize()) {
						stopped = true;
					}
					return;
				} else
				// suppress status message
				if (p[-1] == 0x7c && p - c > 20) {
					return;
				}
			} else if (*p == 0x7f) { // backspace
				*p++ = 0x1b;
				*p++ = '[';
				*p++ = '3';
				*p++ = '~';
			} else if (*p == 8) { // delete
				*p++ = 0x7f;
			} else {
				++p;
			}
		} else
			++p;
	}
	unsigned len = p - c;
	if (len) {
		uint8_t *p = b5;
		*p++ = SSH_MSG_CHANNEL_DATA;  // 1
		*(uint32_t*) p = 0; // channel // 5
		p += 4;
		*(uint32_t*) p = len; // 9 bytes

#if defined LOG_KEYS
		for (unsigned i = 0; i < len; ++i)
			fprintf(keylog, "%02lx ", c[i]);
		fprintf(keylog, "\n");
		fflush(keylog);
#endif

		sendEncrypted(b5, 9 + len);
	}
}

long parseAddr(char *p) {
	int a, b, c, d = -1;
	char *q;
	q = strchr(p, '.');
	if (!q)
		return -1;

	*q++ = 0;
	a = strtoul(p, 0, 10);
	p = q;
	q = strchr(p, '.');
	if (!q)
		return -1;
	*q++ = 0;
	b = strtoul(p, 0, 10);
	p = q;
	q = strchr(p, '.');
	if (!q)
		return -1;
	*q++ = 0;
	c = strtoul(p, 0, 10);
	d = strtoul(q, 0, 10);
	long address = (a & 0xff) << 24 | (b & 0xff) << 16 | (c & 0xff) << 8 | (d & 0xff);
	return address;
}

class ClientChannel;
class ClientForwardChannel;
class ClientForwardListener: public Listener {
	ClientForwardChannel *cfc;
public:
	ClientForwardListener(ClientForwardChannel *cfc_, int sockFd_) :
			cfc(cfc_) {
		sockFd = sockFd_;
		open = true;
	}
	~ClientForwardListener();

	virtual bool isBufferFree() const;
	virtual int processSocketData(void *data, int len);
	virtual void close();
	virtual ClientChannel* getChannel();
};

class ClientForwardChannel: public ClientListenerChannel {
	ClientForwardListener listener;

public:
	ClientForwardChannel(int sockFd_, int channelNo) :
			ClientListenerChannel(channelNo), listener(this, sockFd_) {
		logme(L_DEBUG, "channel %ld socket %ld", getChannelNo(), listener.getSockFd());
	}
	~ClientForwardChannel();

	Listener* getListener() {
		return &listener;
	}

	bool isBufferFree() const {
		return true;
	}
	bool start() {
		return true;
	}
	int processSocketData(void *data, int len);
	int processChannelData(void *data, int len);
	void confirm(uint32_t no, uint32_t mb);

private:
	int innerProcessSocketData(void *data, int len);
};

ClientForwardListener::~ClientForwardListener() {
}

ClientForwardChannel::~ClientForwardChannel() {
	listener.__close();
}

void ClientForwardListener::close() {
	if (open) {
		logme(L_DEBUG, "closing socket %ld", sockFd);
		CloseSocket(sockFd);
		open = false;
	}
}
ClientChannel* ClientForwardListener::getChannel() {
	return cfc;
}

bool ClientForwardListener::isBufferFree() const {
	return true;
}

int ClientForwardListener::processSocketData(void *data, int len) {
	return cfc->processSocketData(data, len);
}

void ClientForwardChannel::confirm(uint32_t no, uint32_t mb) {
	ClientChannel::confirm(no, mb);
	listeners.add(listener.getSockFd(), &listener);
}

int ClientForwardChannel::processSocketData(void *data, int len) {
	int r = 0;
	char *p = (char*) data;
	while (len > 0) {
		int toSend = len > maxBuffer ? maxBuffer : len;
		len -= toSend;
		r += innerProcessSocketData(p, toSend);
		p += toSend;
	}
	return r;
}

int ClientForwardChannel::innerProcessSocketData(void *data, int len) {

	uint8_t *b5 = buffer + 5;
	uint8_t *p = b5;
	*p++ = SSH_MSG_CHANNEL_DATA;  // 1
	*(uint32_t*) p = getRemoteChannelNo(); // channel // 5
	p += 4;
	*(uint32_t*) p = len; // 9 bytes
	p += 4;
	if (data != p) {
		memmove(p, data, len);
	}
	logme(L_DEBUG, "channel %ld/%ld read from socket %ld: forward %ld", getChannelNo(), getRemoteChannelNo(), listener.getSockFd(), len);

	if (isLogLevel(L_ULTRA))
		_dump("sent", data, len);
	return sendEncrypted(b5, 9 + len);
}

int ClientForwardChannel::processChannelData(void *data, int len) {
	logme(L_FINE, "channel %ld/%ld send to socket %ld: %ld", getChannelNo(), getRemoteChannelNo(), listener.getSockFd(), len);
	if (mysend(listener.getSockFd(), data, len))
		return len;
	return -1;
}

class ForwardAcceptor: public Acceptor {
	long bindAddr;
	char const *src;
	long srcPort;
	char const *dest;
	long destPort;

public:
	ForwardAcceptor(char const *src_, long bindAddr_, long bindPort_, char const *dest_, long destPort_) :
			bindAddr(bindAddr_), src(strdup(src_)), srcPort(bindPort_), dest(strdup(dest_)), destPort(destPort_) {
	}

	~ForwardAcceptor() {
		if (open) {
			logme(L_FINE, "closing accept socket %ld", sockFd);
			CloseSocket(sockFd);
			open = false;
		}
		free((char*) src);
		free((char*) dest);
	}

	int getSockFd() const {
		return sockFd;
	}
	bool init() {
		sockFd = socket(AF_INET, SOCK_STREAM, 0);
		logme(L_DEBUG, "forward got socket %ld", sockFd);
		if (sockFd < 0) {
			return false;
		}

		struct sockaddr_in server;
		int c = sizeof(server);

		//Prepare the sockaddr_in structure
		server.sin_family = AF_INET;
		server.sin_addr.s_addr = bindAddr;
		server.sin_port = htons(srcPort);

		//Bind
		if ( bind(sockFd,(struct sockaddr *)&server , sizeof(server)) < 0) {
			logme(L_ERROR, "can't bind on %ld.%ld.%ld.%ld:%ld", (0xff & (server.sin_addr.s_addr >> 24)), (0xff & (server.sin_addr.s_addr >> 16)),
					(0xff & (server.sin_addr.s_addr >> 8)), (0xff & server.sin_addr.s_addr), server.sin_port);
			CloseSocket(sockFd);
			return false;
		}

		open = true;

		logme(L_DEBUG, "forward bound on %ld.%ld.%ld.%ld:%ld", (0xff & (server.sin_addr.s_addr >> 24)), (0xff & (server.sin_addr.s_addr >> 16)),
				(0xff & (server.sin_addr.s_addr >> 8)), (0xff & server.sin_addr.s_addr), server.sin_port);

		long flags = 1;
		IoctlSocket(sockFd, FIONBIO, &flags);

		listen(sockFd, 3);

		return true;
	}

	bool handleAccept(int sockFd_) {
		int no = clientChannels.getFreeIndex();

		uint8_t *b5 = buffer + 5;
		uint8_t *p = b5;

		*p++ = SSH_MSG_CHANNEL_OPEN;
		putString(p, "direct-tcpip");

		putInt32(p, no);
		putInt32(p, 0x7fffffff); // windowsize
		putInt32(p, MAXPACKET); // maxsize
		putString(p, dest);
		putInt32(p, destPort);

		struct sockaddr_in sin;
		socklen_t len = sizeof(sin);
		if (0 == getsockname(sockFd_, (struct sockaddr* )&sin, &len)) {
			char buf[3 * 4 + 3 + 1];
			snprintf(buf, 3 * 4 + 3 + 1, "%ld.%ld.%ld.%ld", (0xff & (sin.sin_addr.s_addr >> 24)), (0xff & (sin.sin_addr.s_addr >> 16)),
					(0xff & (sin.sin_addr.s_addr >> 8)), (0xff & sin.sin_addr.s_addr));
			putString(p, buf);
			putInt32(p, sin.sin_port);
			logme(L_DEBUG, "accept on %ld, %s:%ld -> %s:%ld", sockFd_, buf, sin.sin_port, dest, destPort);
		} else {
			putString(p, src);
			putInt32(p, srcPort);
			logme(L_DEBUG, "accept on %ld -> %s:%ld", sockFd_, dest, destPort);
		}

		if (!sendEncrypted(b5, p - b5))
			return false;

		auto fl = new ClientForwardChannel(sockFd_, no);
		clientChannels.add(no, fl);

		logme(L_DEBUG, "success accepting %ld -> %s:%ld", sockFd_, dest, destPort);
		return true;
	}
};

bool addForwardAcceptor(char const *s) {
	char *listenAddress = strdup(s);
	char *listenPort = strchr(s, ':');
	if (!listenPort)
		return false;
	*listenPort++ = 0;
	char *destAddress = strchr(listenPort, ':');
	if (!destAddress)
		return false;
	*destAddress++ = 0;

	char *destPort = strchr(destAddress, ':');
	if (!destPort) {
		destPort = destAddress;
		destAddress = listenPort;
		listenPort = listenAddress;
		listenAddress = strdup("0.0.0.0");
	} else
		*destPort++ = 0;

	long listenA = parseAddr(listenAddress);
	if (listenA == -1) {
		logme(L_ERROR, "invalid listenAddress %s", listenAddress);
		return false;
	}

	long listenP = atol(listenPort);
	long toP = atol(destPort);

	logme(L_DEBUG, "forward %s:%ld to %s:%ld", listenAddress, listenP, destAddress, toP);

	ForwardAcceptor *fwd = new ForwardAcceptor(listenAddress, listenA, listenP, destAddress, toP);

	initacceptors.push(fwd);

	return true;
}

static void printUsage() {
	puts(__VERSION);
	puts("USAGE: amigassh [options] [user@]host[:port] [command [args...]]");
	puts("    -?            display this help");
	puts("    -c <file>     select the config file");
	puts("                  defaults to envarc:.ssh/ssh_config");
	puts("    -i <file>     select the private key file for public key authentication");
	puts("                  defaults to envarc:.ssh/id_ed25519");
	puts("    -L [bind_address:]port:host:hostport");
	puts("                  listen at bind_address:port and forward to host:hostport");
	puts("    -p <port>     connect to the host at port <port>");
	puts("    -T            don't allocate a pseudo terminal");
	puts("    -v <n>        set verbosity, defaults to 0 = OFF");
	puts("    --ciphers <n> use the ciphers in the given order:");
	puts("                  1=aes128-gcm, 2=chacha20-poly1305");
	puts("                  defaults to n=21");
	puts("    --noesc       don't handle ESC sequences, default is on if interactive");
}

static void parseParams(unsigned argc, char **argv) {
	char *user = getenv("USER");
	if (user)
		username = user;
	char *term = getenv("TERM");
	if (term)
		TERM = term;

	escape = IsInteractive(stdin);

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
			case 'L':
				if (arg[2]) {
					if (!addForwardAcceptor(&arg[2]))
						goto invalid;
					continue;
				}
				if (i + 1 == argc)
					goto missing;
				if (!addForwardAcceptor(argv[++i]))
					goto invalid;
				continue;
			case 'T':
				pty = false;
				continue;
			case '-':
				if (0 == strcmp(arg, "--noesc")) {
					escape = 0;
					continue;
				}
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

		if (normal == 0) {
			char *colon = strchr(arg, ':');
			if (colon) {
				*colon++ = 0;
				port = atoi(colon);
				portSet = 1;
			}
			char *at = strchr(arg, '@');
			if (at) {
				*at++ = 0;
				username = arg;
				usernameSet = 1;
				arg = at;
			}
			hostname = arg;
		} else if (normal == 1) {
			command = strdup(arg);
		} else {
			char * c = concat(command, " ", arg, 0);
			if (!c) {
				error = ERROR_NOMEM;
				return;
			}
			free(command);
			command = c;
		}

		++normal;
		continue;
	}
	return;

	usage: printUsage();
	exit(0);

	missing: printf("missing parameter for %s\n", arg);
	exit(10);

	invalid: printf("invalid option %s\n", arg);
	exit(10);
}

struct Library *IconBase = 0;
char __stdiowin[128] = "CON://///AUTO/CLOSE/WAIT";
extern struct WBStartup *_WBenchMsg;
extern "C" void __parseIcon(void) {
	char buff[256];
	struct WBStartup *wbstartup = _WBenchMsg;
	if (!wbstartup)
		return;
	IconBase = OldOpenLibrary("icon.library");
	if (!IconBase)
		return;
	struct WBArg *wba = wbstartup->sm_ArgList;
	int l = strlen((char const*) wba->wa_Name);
	if (l < 254) {
		NameFromLock(wba->wa_Lock, (STRPTR )buff, 254 - l);
		strcat((char*) buff, "/");
		strcat((char*) buff, (char const*) wba->wa_Name);
		struct DiskObject *disko = GetDiskObject((char* )buff);
		if (disko) {
			UBYTE *tt;
			CONST_STRPTR *dot = (CONST_STRPTR*) disko->do_ToolTypes;
			CONST_STRPTR s = "HOST";
			tt = FindToolType(dot, s);
			if (tt) {
				hostname = strdup((char const*) tt);
				hostnameSet = 1;
			}
			tt = FindToolType(dot, "PORT");
			if (tt) {
				port = atoi((char*) tt);
				portSet = 1;
			}
			tt = FindToolType(dot, "LOGLEVEL");
			if (tt) {
				setLogLevel((DebugLevel)atoi((char*) tt));
				loglevelSet = 1;
			}
			tt = FindToolType(dot, "USER");
			if (tt) {
				username = strdup((char const*) tt);
				usernameSet = 1;
			}
			tt = FindToolType(dot, "COMMAND");
			if (tt)
				command = strdup((char const*) tt);
			tt = FindToolType(dot, "CONSOLE");
			if (tt) {
				strncpy(__stdiowin, (char const*) tt, 127);
				consoleSet = 1;
			}
			tt = FindToolType(dot, "TERM");
			if (tt) {
				TERM = strdup((char const*) tt);
				termSet = 1;
			}
			tt = FindToolType(dot, "KEYFILE");
			if (tt) {
				keyFile = strdup((char const*) tt);
				keyfileSet = 1;
			}
			tt = FindToolType(dot, "LOCALFORWARD");
			if (tt) {
				addForwardAcceptor((char const*) tt);
			}

			FreeDiskObject(disko);
		}
	}
	CloseLibrary(IconBase);
}
ADD2INIT(__parseIcon, -41);

extern void parseConfigFile(int ssh);

__stdargs int main(int argc, char **argv) {
	logme(L_FINE, __VERSION);

	if (argc) // not from workbench
		parseParams(argc, argv);

	parseConfigFile(true);

	clientChannels.add(0, new ConsoleChannel(pty, command));
#if defined LOG_KEYS
keylog = Open("key.log", MODE_NEWFILE);
#endif

	runClient();
#if defined LOG_KEYS
Close(keylog);
#endif

	return error;
}
