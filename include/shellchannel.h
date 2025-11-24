/*
 * AmigaSSH - Shell channel implementation
 *
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
 * Project: AmigaSSH - SSH2 client/server suite for Amiga
 * Purpose: Provide interactive shell channel support with command history,
 *          PTY handling, and line editing
 *
 * Features:
 *  - History ring buffer for command recall
 *  - ShellChannel class with PTY, shell, and exec modes
 *  - Support for prompt display, autocomplete, and line editing
 *  - Break port handling, timeout checks, and session lifecycle management
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management and session integration.
 *
 * Author's intent:
 *  Deliver a clear, maintainable shell channel implementation to support
 *  interactive SSH sessions on Amiga systems.
 * ----------------------------------------------------------------------
 */
#ifndef SHELLCHANNEL_H_
#define SHELLCHANNEL_H_

#include "channel.h"

/**
 * A ring buffer to maintain the command history of a shell.
 */
class History {
	int top;
	int pos;
	int end;
	int max;
	char ** data;
public:
	History(int sz) : top(sz - 1), pos(0), end(0), max(sz) {
		data = new char *[sz];
		memset(data, 0, sizeof(char*) * sz);
	}
	~History() {
		for (int i = 0; i < max; ++i)
			free(data[i]);
		delete [] data;
	}
	char * getNext() {
		if (pos == end)
			return 0;
		++pos;
		if (pos == max)
			pos = 0;
		return data[pos];
	}
	char * getPrev() {
		int prev = pos ? pos - 1 : max - 1;
		if (prev == top)
			return 0;
		pos = prev;
		return data[prev];
	}
	void put(char * t) {
		// append only if it differs from last
		int endm1 = end ? end - 1 : max - 1;
		if (endm1 == top || strcmp(t, data[endm1])) {
			if (end == top)
				free(data[end]);
			data[end] = t;
			if (++end == max)
				end = 0;
		} else
			free(t);
		pos = end;
	}
	void toEnd() {
		pos = end;
	}
};

extern unsigned stackSize;
extern char const * homeDir;

class ShellChannel : public Channel {
	bool pty;
	bool shell;
	bool exec;

	bool localEcho;

	unsigned stackSize;
	BPTR dir;

	volatile bool running;
	volatile bool done;
	struct MsgPort * breakPort1, *breakPort2;
	struct Message * pending;
	struct Message * waiting;
	struct timeval until;

	char * xpos; // position into line
	char * xend; // end position into line
	char line[CHUNKSIZE];
	char outbuffer[CHUNKSIZE]; // buffer for output
	char xbuffer[CHUNKSIZE];   // buffer for line operations

	unsigned inBufferLen;
	char * inBuffer;

	History history;

	unsigned rows, cols;
public:
	ShellChannel(SshSession * server, uint32_t channel, ChannelType type);
	~ShellChannel();

	void cmdCD(char * q);
	bool startCommand(char const *);
	bool startCommand();
	bool endCommand();
	bool isDone() const { return done;}
	void prompt();
	void autocomplete();
	int handleData(char * data, unsigned len);

	char * redrawRestOfLine(char *);
	char * cursorLeft(char * out, int slen);
	char * cursorRight(char * out, int slen);

	bool hasPty() const { return pty; }
	void setPty(bool p) { pty = p;}
	void setDimension(unsigned cols, unsigned rows) {
		this->cols = cols;
		this->rows = rows;
	}
	bool hasShell() const { return shell; }
	void setShell(bool s) { shell = s; }
	bool hasExec() const { return exec; }
	void setExec(bool e) { exec = e; }
	bool isPending() const { return pending != 0;}
	void setPending(struct Message * m) { pending = m;}
	bool isWaiting() const { return waiting != 0;}
	void setWaiting(struct Message * m) { waiting = m;}
	struct MsgPort * setBreakPort(struct MsgPort * p1, struct MsgPort * p2);
	bool hasBreakPort(struct MsgPort * p) const { return breakPort1 == p || breakPort2 == p; }
	int getAvail() const { return xend - line;}
	struct timeval * getUntil() { return &until;}

	static void startProc();
	static void endProc();

	int read(char * to, int len);
	int write(char * from, int len);

	virtual void sendBreak();
	virtual void checkTimeout(struct timeval * tv);
	virtual void abort();
};


#endif /* SHELLCHANNEL_H_ */
