/*
 * bebbosshd - simple SSH daemon
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
 * Project: bebbossh - SSH daemon for Amiga
 * Purpose: Provide server-side SSH2/SFTP support
 *
 * Features:
 *  - Host key management (Ed25519)
 *  - Client session handling and PTY allocation
 *  - Integration with AmigaDOS message ports
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with bsdsocket.library and timer.device.
 *
 * Author's intent:
 *  Allow Amiga systems to act as SSH servers for secure remote access.
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include "platform.h"

#if BEBBOSSH_AMIGA_API
#include <amistdio.h>
#include <clib/alib_protos.h>
#include <devices/timer.h>
#include <dos/dostags.h>
#include <hardware/custom.h>
#include <proto/dos.h>
#include <proto/exec.h>
#include <proto/socket.h>
#include <proto/timer.h>
#if BEBBOSSH_AROS
#include <bsdsocket/socketbasetags.h>
#endif

#define DPTR BPTR

#else
#include "amiemul.h"
#endif

#include <aes.h>
#include <ed25519.h>
#include <forwardchannel.h>
#include <gcm.h>
#include <md.h>
#include <mime.h>
#include <ssh.h>
#include <log.h>
#include <test.h>
#include <rand.h>
#include <sshsession.h>
#include "revision.h"
#include "channel.h"
#include "shellchannel.h"

static __far char theBuffer[2*CHUNKSIZE - 256];

#if BEBBOSSH_AMIGA_API
struct SignalSemaphore theLock;

/* DOS FileHandle functions */
LONG readFx;
LONG writeFx;
LONG flushFx;

struct FileHandle *theInput;
long theInputSize;
struct FileHandle *theOutput;
#else
pthread_mutex_t theLock;
#endif

/* host key */
uint8_t hostPK[32];
uint8_t hostSK[64];

/* config stuff */
int serverPort = 22;
int serverAddress = INADDR_ANY;
#if BEBBOSSH_AROS
int listenBacklog = 16;
#define BEBBOSSH_ACCEPT_BURST 1
#else
int listenBacklog = 8;
#define BEBBOSSH_ACCEPT_BURST 1
#endif
#if BEBBOSSH_AROS
unsigned stackSize = 1048576;
#else
unsigned stackSize = 4096;
#endif
char const * homeDir = "RAM:";
BPTR curDir, orgDir;

char const * bsdName = "bsdsocket.library";
#if BEBBOSSH_AMIGA_API
char const * configName = "ENVARC:ssh/sshd_config";
char const * passwords = "ENVARC:ssh/passwd";
char const * hostKeyName = "ENVARC:ssh/ssh_host_ed25519_key";
#if BEBBOSSH_AROS
static char const * arosFallbackHostKeyName = "PROGDIR:ssh_host_ed25519_key";
static char const * arosFallbackConfigName = "PROGDIR:sshd_config";
#endif
#else
char const * configName = "/etc/ssh/sshd_config";
char const * passwords = "/etc/ssh/passwd";
char const * hostKeyName = "/etc/ssh/ssh_host_ed25519_key";
#endif

bool hasAes = true;
bool hasChacha = true;
extern char const * AES128;
extern char const * CHACHA20;

/* This task and its message port */
struct Task * thisTask;
struct MsgPort * port;

struct Library *SocketBase = 0;
int acceptSock = -1;
int stopped;
bool timerOn;
int noopMask;

enum Errors {
	NO_ERROR,
	ERR_KEYFILE = 10,
	ERR_IOFX,
	ERR_MESSAGE_PORT,
	ERR_EXT_IO,
	ERR_TIMER,
	ERR_BSD,
	ERR_LISTEN_SOCKET,
	ERR_BIND,
};
Errors error;

Stack<Listener> *listenersPtr;
static Stack<SshSession> *clientsPtr;
#define listeners (*listenersPtr)
#define clients (*clientsPtr)

#if BEBBOSSH_AMIGA_API
struct MsgPort * timerPort;
struct timerequest * timerIO;
struct Device * TimerBase = 0;

__stdargs struct IORequest* CreateExtIO(CONST struct MsgPort *port, LONG iosize) {
	struct IORequest *ioreq = NULL;
	if (port && (ioreq = (struct IORequest*) malloc(iosize))) {
		memset(ioreq, 0, iosize);
		ioreq->io_Message.mn_Node.ln_Type = NT_REPLYMSG;
		ioreq->io_Message.mn_ReplyPort = (struct MsgPort*) port;
		ioreq->io_Message.mn_Length = iosize;
	}
	return ioreq;
}

/*
 * Open a dummy file to steal the file handling functions.
 * Close and delete it.
 */
void grabFx() {
	// get the input file handle to abuse it...
	BPTR i = Input();
	char * ic = (char *)BADDR(i);
	theInput = (struct FileHandle *)ic;
	theInputSize = *(long *)(ic - 4) - 4;

	// same for the output file handle
	BPTR o = Output();
	char * oc = (char *)BADDR(o);
	theOutput = (struct FileHandle *)oc;

	CONST_STRPTR n = "ram:__xyz__";
	BPTR bptr = Open(n, MODE_NEWFILE);
	if (bptr) {
		struct FileHandle * fh = (struct FileHandle *)BADDR(bptr);
		readFx = fh->fh_Func1;
		writeFx = fh->fh_Func2;
		flushFx = fh->fh_Func3;
		Close(bptr);
		DeleteFile(n);
	}
}

char const* getBSTR(BPTR bp) {
	static char nameBuffer[256];
	char const *bstr = (char const*) BADDR(bp);
	int sz = (unsigned char)*bstr++;
	strncpy(nameBuffer, bstr, sz);
	nameBuffer[sz] = 0;
	return nameBuffer;
}

// needs synchronization with the main task, it gets called from the commands
ShellChannel * findByBreakPort(struct MsgPort * mp) {
	ShellChannel * sc = 0;
	ObtainSemaphore(&theLock);
	int sz = clients.getMax();
	for (int i = 0; i < sz; ++i) {
		SshSession * s = clients[i];
		if (!s)
			continue;
		sc = s->findShellChannelByBreakPort(mp);
		if (sc)
			break;
	}
	ReleaseSemaphore(&theLock);
	return sc;
}
/**
 * Handle the messages.
 * - end message, if a command has ended. Identified by replyport == timerPort and pri==42
 * - DosPacket to a synthetic file handle.
 */
void handleMsg(struct Message * msg) {
	if (msg) {
		struct DosPacket *packet = getDosPacket(msg);
		packet->dp_Res1 = DOSFALSE;

		logme(L_DEBUG, "handle message ACTION=%ld arg1=%08lX port=%08lX", packet->dp_Type, packet->dp_Arg1, packet->dp_Port);
		switch (packet->dp_Type) {
		/*
		 * Return DOSTRUE if data is present.
		 * Enqueue to wait if not - don't answer that packet!
		 */
		case ACTION_WAIT_CHAR: {
			ShellChannel *sc = findByBreakPort(packet->dp_Port);
			if (sc) {
				if (!stopped || sc->isWaiting()) {
					int timeout = packet->dp_Arg1;
					int avail = sc->getAvail();
					if (avail) {
						sc->setWaiting(0);
						packet->dp_Res1 = DOSTRUE;
						packet->dp_Res2 = 1; // one line !?! we don' count 'em
						logme(L_TRACE, "ACTION_WAIT_CHAR for %s has data", sc->getName());
					} else {
						logme(L_TRACE, "ACTION_WAIT_CHAR for %s no data waiting for %ld", sc->getName(), timeout);
						sc->setWaiting(msg);
						struct timeval * tv = sc->getUntil();
						GetSysTime(tv);
						tv->tv_micro += timeout;
						return;
					}
				}
			} else {
				packet->dp_Res1 = DOSFALSE;
				packet->dp_Res2 = ERROR_NO_MORE_ENTRIES;
				logme(L_TRACE, "ACTION_WAIT_CHAR for %s NO data", sc->getName());
			}
		} break;
		case ACTION_READ: {
			ShellChannel * sc = (ShellChannel *) packet->dp_Arg1;
			sc->setPending(0);

			char * buffer =  (char *)packet->dp_Arg2;
			LONG len = packet->dp_Arg3;
			int avail = sc->getAvail();
			int toRead = avail < len ? avail : len;
			if (toRead)
				toRead = sc->read(buffer, toRead);
			if (toRead) {
				packet->dp_Res1 = toRead;
				packet->dp_Res2 = DOSTRUE;
				logme(L_TRACE, "ACTION_READ %s read %ld bytes", sc->getName(), toRead);
			} else {
				if (!stopped) {
					logme(L_TRACE, "enqueue ACTION_READ %s msg %08lX -> port %08lX", sc->getName(), msg, packet->dp_Port);
					sc->setPending(msg);
					return;
				}
				logme(L_TRACE, "ACTION_READ %s failed", sc->getName());
				packet->dp_Res1 = DOSTRUE;
				packet->dp_Res2 = ERROR_ACTION_NOT_KNOWN;
			}
		} break;
		case ACTION_WRITE: {
			ShellChannel * sc = (ShellChannel *) packet->dp_Arg1;
			char * buffer =  (char *)packet->dp_Arg2;
			LONG len = packet->dp_Arg3;

			logme(L_DEBUG, "ACTION_WRITE: %s %ld bytes %02lx", sc->getName(), len, buffer[0]);
			int sent;
			if (len > 0)
				sent = sc->write(buffer, len);
			else
				sent = 0;
			packet->dp_Res1 = sent;
			packet->dp_Res2 = DOSTRUE;
		}
			break;
		case ACTION_SCREEN_MODE:
			logme(L_TRACE, "ACTION_SCREEN_MODE");
			packet->dp_Res1 = DOSTRUE;
			break;
		case ACTION_CHANGE_SIGNAL: {
			ShellChannel *sc = (ShellChannel*) packet->dp_Arg1;

				/* set new port. */
			struct MsgPort * oport = sc->setBreakPort((struct MsgPort*) packet->dp_Arg2, (struct MsgPort*)packet->dp_Arg3);
			logme(L_DEBUG, "ACTION_CHANGE_SIGNAL %s new port %08lX old port %08lX", sc->getName(), (void *)packet->dp_Arg2, oport);

			packet->dp_Res1 = DOSTRUE;
			packet->dp_Res2 = (SIPTR) oport; // report old/current port
		}
			break;
		case ACTION_FINDOUTPUT:
		case ACTION_FINDINPUT: { // FINDINPUT from console? strange...
			ShellChannel *sc = findByBreakPort(packet->dp_Port);
			struct FileHandle *fh = (struct FileHandle*) BADDR(packet->dp_Arg1);
			char const * name = getBSTR((BPTR) packet->dp_Arg3);
			logme(L_DEBUG, "ACTION_FINDINPUT: %s lock=%08lX name=%s @%08lX %08lX", sc->getName(), (void *)packet->dp_Arg2, name, fh->fh_Type, packet->dp_Port);

			memset(fh, 0, sizeof(struct FileHandle));
			fh->fh_Port = 1;
			fh->fh_Type = port;
			fh->fh_Pos = fh->fh_End = -1;
			fh->fh_Arg1 = (SIPTR)sc;

			if (sc) {
				packet->dp_Res1 = DOSTRUE;
				packet->dp_Res2 = 0;
			}
		}break;
		case ACTION_END: {
			logme(L_TRACE, "ACTION_END");

			packet->dp_Res1 = DOSTRUE;
			packet->dp_Res2 = 0;
		} break;
		case ACTION_SEEK:
			logme(L_TRACE, "ACTION_SEEK: not supported");
			packet->dp_Res1 = DOSTRUE;
			packet->dp_Res2 = ERROR_ACTION_NOT_KNOWN;
			break;
		case ACTION_DISK_INFO:
		case ACTION_COPY_DIR_FH:
		case ACTION_PARENT_FH:
		case ACTION_EXAMINE_ALL:
		case ACTION_EXAMINE_FH:
			logme(L_TRACE, "action %ld not implemented", packet->dp_Type);
			packet->dp_Res2 = ERROR_ACTION_NOT_KNOWN;
			break;
		default:
			logme(L_DEBUG, "Unhandled action %ld", packet->dp_Type);
		}
		ReplyPkt(packet, packet->dp_Res1, packet->dp_Res2);
	}
}

void startTimer() {
	logme(L_ULTRA, "starting new timer");
	timerIO->tr_node.io_Command = TR_ADDREQUEST;
	timerIO->tr_time.tv_secs = 0;
	timerIO->tr_time.tv_micro = 32768 + (rand() & 32767);
	SendIO(&timerIO->tr_node);
	timerOn = true;
}


void timeoutWaitForChar() {
	struct timeval now;
	GetSysTime(&now);
	uint32_t sz = clients.getMax();
	for (int i = 0; i < sz; ++i) {
		auto c = clients[i];
		if (c)
			c->checkTimeout(&now);
	}
}
#endif

int cancelRunning() {
	int running = 0;
	ObtainSemaphore(&theLock);
	int sz = clients.getMax();
	for (int i = 0; i < sz; ++i) {
		SshSession * cs = clients[i];
		if (!cs)
			continue;

		if (cs->isAlive()) {
			cs->sendBreak();
			++running;
		} else {
			cs->close();
		}
	}
	ReleaseSemaphore(&theLock);
	if (running)
		logme(L_WARN, "%ld clients are still busy", running);
	return running;
}

// prune dead clients
void pruneDeadClients() {
	// needs synchronization with the runnning commands
	ObtainSemaphore(&theLock);
	int sz = clients.getMax();
	for (int i = 0; i < sz; ++i) {
		SshSession * cs = clients[i];
		if (!cs || cs->isOpen() || cs->isAlive())
			continue;

		logme(L_DEBUG, "pruning server %s socket=%ld", cs->name, cs->getSockFd());
		clients.remove(cs->getSockFd());
		listeners.remove(cs->getSockFd());

#ifdef PROFILE
		puts("stopping");
		stopped = 1;
#endif

		delete cs;
	}
	ReleaseSemaphore(&theLock);
}



void checkFinished() {
	uint32_t sz = clients.getMax();
	for (int i = 0; i < sz; ++i) {
		auto c = clients[i];
		if (c)
			c->checkFinished();
	}
}

static void cleanupSessions() {
	if (clientsPtr) {
		uint32_t sz = clientsPtr->getMax();
		for (uint32_t i = 0; i < sz; ++i) {
			SshSession *cs = clientsPtr->remove(i);
			if (!cs)
				continue;
			if (listenersPtr)
				listenersPtr->remove(cs->getSockFd());
			cs->close();
			delete cs;
		}
		delete clientsPtr;
		clientsPtr = 0;
	}

	if (listenersPtr) {
		uint32_t sz = listenersPtr->getMax();
		for (uint32_t i = 0; i < sz; ++i) {
			Listener *l = listenersPtr->remove(i);
			delete l;
		}
		delete listenersPtr;
		listenersPtr = 0;
	}
}

void cleanup() {
	// no more connections
	if (acceptSock != -1) {
		logme(L_FINE, "closing listen socket %ld", acceptSock);
		CloseSocket(acceptSock);
		acceptSock = -1;
	}
	cleanupSessions();
#if BEBBOSSH_AMIGA_API
	if (SocketBase) {
		logme(L_FINE, "closing %s", bsdName);
		CloseLibrary(SocketBase);
		SocketBase = 0;
	}

	if (TimerBase) {
		logme(L_FINE, "closing timer.device");
		if (timerOn && timerIO) {
			if (!CheckIO(&timerIO->tr_node)) {
				logme(L_DEBUG, "abort IO");
				AbortIO(&timerIO->tr_node);
			}
			WaitIO(&timerIO->tr_node);
		}
		timerOn = false;
		CloseDevice(&timerIO->tr_node);
		TimerBase = 0;
	}

	if (timerIO) {
		logme(L_FINE, "free timer request");
#if BEBBOSSH_AROS && defined(BEBBOSSH_AROS_MINCRT)
		DeleteIORequest(timerIO);
#else
		free(timerIO);
#endif
		timerIO = 0;
	}

	if (timerPort) {
		logme(L_FINE, "free timer message port");
		DeleteMsgPort(timerPort);
		timerPort = 0;
	}

	if (port) {
		logme(L_FINE, "free default message port");
		DeleteMsgPort(port);
		port = 0;
	}

	if (orgDir)
		CurrentDir(orgDir);
	orgDir = 0;
	if (curDir) {
		UnLock(curDir);
		curDir = 0;
	}
#endif
}

void abortAll() {
	uint32_t sz = clients.getMax();
	for (int i = 0; i < sz; ++i) {
		auto c = clients[i];
		if (c)
			c->abort();
	}
}

static bool init() {
#if BEBBOSSH_AMIGA_API
#if BEBBOSSH_AROS
	readFx = writeFx = flushFx = 0;
	theInput = theOutput = 0;
	theInputSize = 0;
#else
	grabFx();
	if (!theOutput || !theInput)
		logme(L_ERROR, "no working i/o");
#endif

#if !(BEBBOSSH_AROS && defined(BEBBOSSH_AROS_MINCRT))
	curDir = Lock(homeDir, SHARED_LOCK);
	if (curDir)
		orgDir = CurrentDir(curDir);
#endif

	port = CreateMsgPort();
	if (0 == port) {
		error = ERR_MESSAGE_PORT;
		return false;
	}
	logme(L_FINE, "got default message port %08lX", port);

	timerPort = CreateMsgPort();
	if (0 == timerPort) {
		error = ERR_MESSAGE_PORT;
		return false;
	}
	logme(L_FINE, "got timer message port");

#if BEBBOSSH_AROS && defined(BEBBOSSH_AROS_MINCRT)
	timerIO = (struct timerequest *)CreateIORequest(timerPort, sizeof(struct timerequest));
#else
	timerIO = (struct timerequest *)CreateExtIO(timerPort, sizeof(struct timerequest));
#endif
	if (0 == timerIO) {
		error = ERR_EXT_IO;
		return false;
	}
	logme(L_FINE, "got timer request");

	if (OpenDevice(TIMERNAME, UNIT_VBLANK, &timerIO->tr_node, 0)) {
		error = ERR_TIMER;
		return false;
	}
	TimerBase = timerIO->tr_node.io_Device;
	logme(L_FINE, "opened timer device");

	SocketBase = OpenLibrary(bsdName, 3);
	if (0 == SocketBase) {
		error = ERR_BSD;
		return false;
	}
	logme(L_FINE, "opened %s", bsdName);

	SocketBaseTags(SBTM_SETVAL(SBTC_BREAKMASK), 0, TAG_DONE);
#endif

	//Create socket
	acceptSock = socket(AF_INET, SOCK_STREAM, 0);
	if (acceptSock == -1) {
		error = ERR_LISTEN_SOCKET;
		return false;
	}
	logme(L_FINE, "create listen socket %ld", acceptSock);

#if BEBBOSSH_LINUX
	int yes = 1;
	setsockopt(acceptSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif

	return true;
}

void parseNoop(char const * s) {
	if (0 == stricmp(s, "off"))
		noopMask = 0;
	else if (0 == stricmp(s, "some"))
		noopMask = 0x1f;
	else if (0 == stricmp(s, "many"))
		noopMask = 7;
	else
		logme(L_WARN, "unknown value for Noop: %s", s);
}

void readIni() {
	BPTR ini = Open(configName, MODE_OLDFILE);
#if BEBBOSSH_AROS
	if (!ini) {
		ini = Open(arosFallbackConfigName, MODE_OLDFILE);
		if (ini)
			configName = arosFallbackConfigName;
	}
#endif
	if (!ini) {
		logme(L_WARN, "can't open `%s`", configName);
		return;
	}

	for(;;) {
		char buf[256];
		char * s = FGets(ini, buf, 256);
		if (!s)
			break;

		char * p = (char *)splitLine(s);
		if (!p)
			continue;

		// s = keyword, p = parameter

		logme(L_DEBUG, "sshd_config: %s %s", s, p);
		if (0 == stricmp("SendNoop", s)) {
			parseNoop(p);
		} else
		if (0 == stricmp("Ciphers", s)) {
			hasAes = 0 != strstr(p, AES128);
			hasChacha =  0 != strstr(p, CHACHA20);
			if (!(hasAes | hasChacha)){
				logme(L_WARN, "no valid ciphers given in %s: %s", configName, s);
			}
		} else
		if (0 == stricmp("DebugLevel", s)) {
			parseLogLevel(p);
		} else
		if (0 == stricmp("Passwords", s)) {
			passwords = strdup(p);
		} else
		if (0 == stricmp("HomeDir", s)) {
			homeDir = strdup(p);
		} else
		if (0 == stricmp("HostKey", s)) {
			hostKeyName = strdup(p);
		} else
		if (0 == stricmp("Stack", s)) {
			stackSize = strtoul(p, 0, 10);
			if (stackSize < 4096)
				stackSize = 4096;
		} else
		if (0 == stricmp("Port", s)) {
			serverPort = strtoul(p, 0, 10);
		} else
		if (0 == stricmp("ListenBacklog", s)) {
			listenBacklog = strtoul(p, 0, 10);
			if (listenBacklog < 1)
				listenBacklog = 1;
			if (listenBacklog > 64)
				listenBacklog = 64;
		} else
		if (0 == stricmp("ListenAddress", s)) {
			int a, b, c, d = -1;
			char * q;

			q = strchr(p, '.');
			if (q) {
				*q++ = 0;
				a = strtoul(p, 0, 10);
				p = q;
				q = strchr(p, '.');
				if (q) {
					*q++ = 0;
					b = strtoul(p, 0, 10);
					p = q;
					q = strchr(p, '.');
					if (q) {
						*q++ = 0;
						c = strtoul(p, 0, 10);
						d = strtoul(q, 0, 10);
					}
				}
			}

			if (d == -1) {
				logme(L_WARN, "sshd_config: invalid ListenAddress: %s", p);
			} else {
				serverAddress = (a & 0xff) << 24 | (b & 0xff) << 16 | (c & 0xff) << 8 | (d & 0xff);
			}
		} else {
			logme(L_WARN, "sshd_config: unknown directive: %s %s", s, p);
		}
	}

	Close(ini);
	return;
}

void sendNoop() {
	char c[2];
	uint32_t sz = listeners.getMax();
	for (int i = 0; i < sz; ++i) {
		auto l = listeners[i];
		if (!l)
			continue;
		randfill(&c, 1);
		if (0 == (c[0] & noopMask))
			l->noop();
	}
}

static void printUsage() {
	puts(__VERSION);
	puts("USAGE: amigasshd [options]");
	puts("    -?            display this help");
	puts("    -p <port>     use the given port <port>");
	puts("    -v <n>        set verbosity, defaults to 0 = OFF");
#if BEBBOSSH_AROS
	puts("    -A <file>     use the given password file");
	puts("    -H <dir>      use the given home directory");
	puts("    -K <file>     use the given Ed25519 host key");
#endif
}

static void parseParams(unsigned argc, char **argv) {
	unsigned normal = 0;
	char *arg = 0;

	for (unsigned i = 1; i < argc; ++i) {
		arg = argv[i];
		if (normal == 0 && arg[0] == '-') {
			switch (arg[1]) {
			case '?':
				goto usage;
			case 'p':
				if (arg[2]) {
					serverPort = atoi(&arg[2]);
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				serverPort = atoi(argv[++i]);
				continue;
			case 'v':
				if (arg[2]) {
					setLogLevel((DebugLevel)atoi(&arg[2]));
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				setLogLevel((DebugLevel)atoi(argv[++i]));
				continue;
#if BEBBOSSH_AROS
			case 'A':
				if (arg[2]) {
					passwords = strdup(&arg[2]);
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				passwords = strdup(argv[++i]);
				continue;
			case 'H':
				if (arg[2]) {
					homeDir = strdup(&arg[2]);
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				homeDir = strdup(argv[++i]);
				continue;
			case 'K':
				if (arg[2]) {
					hostKeyName = strdup(&arg[2]);
					continue;
				}

				if (i + 1 == argc)
					goto missing;
				hostKeyName = strdup(argv[++i]);
				continue;
#endif
			default:
				goto invalid;
			}
		}
		++normal;
		continue;
	}
	if (!normal)
		return;

	usage:
	printUsage();
	exit(0);

	missing: printf("missing parameter for %s\n", arg);
	exit(10);

	invalid: printf("invalid option %s\n", arg);
	exit(10);
}

__stdargs int main(int argc, char *argv[]) {
#if BEBBOSSH_AROS
	logme(L_DEBUG, "bebbosshd/AROS: start");
#endif
	listenersPtr = new Stack<Listener>();
	clientsPtr = new Stack<SshSession>();
	atexit(cleanup);

	InitSemaphore(&theLock);

#if BEBBOSSH_AROS && defined(BEBBOSSH_AROS_MINCRT)
	hostKeyName = "PROGDIR:HOSTKEY";
	passwords = "PROGDIR:PASSWD";
	homeDir = "AROS:";
	setLogLevel(L_NONE);
#else
	readIni();
#endif
#if BEBBOSSH_AROS
	logme(L_DEBUG, "bebbosshd/AROS: config read");
#endif

	parseParams(argc, argv);
#if BEBBOSSH_AROS
	logme(L_DEBUG, "bebbosshd/AROS: params parsed, port %ld", (LONG)serverPort);
#endif

	if (!loadEd25519Key(hostPK, hostSK, hostKeyName)) {
#if BEBBOSSH_AROS
		logme(L_DEBUG, "bebbosshd/AROS: trying PROGDIR host key");
		if (!loadEd25519Key(hostPK, hostSK, arosFallbackHostKeyName)) {
			return error = ERR_KEYFILE;
		}
#else
		return error = ERR_KEYFILE;
#endif
	}
#if BEBBOSSH_AROS
	logme(L_DEBUG, "bebbosshd/AROS: host key loaded");
#endif

	do { // while (0);
		if (!init())
			break;
#if BEBBOSSH_AROS
		logme(L_DEBUG, "bebbosshd/AROS: init ok");
#endif

#if BEBBOSSH_AMIGA_API
		thisTask = FindTask(NULL);
		logme(L_TRACE, "self %08lX mp %08lX", thisTask, &((struct Process *)thisTask)->pr_MsgPort);

		ULONG portMask = (1 << port->mp_SigBit);
		ULONG timerMask = (1 << timerPort->mp_SigBit);
#endif

		struct sockaddr_in server;

		//Prepare the sockaddr_in structure
		server.sin_family = AF_INET;
		server.sin_addr.s_addr = serverAddress;
		server.sin_port = htons(serverPort);
#if BEBBOSSH_AROS
		logme(L_DEBUG, "bebbosshd/AROS: binding port %ld", (LONG)serverPort);
#endif

		//Bind
		if ( bind(acceptSock,(struct sockaddr *)&server , sizeof(server)) < 0) {
			logme(L_ERROR, "can't bind on %ld.%ld.%ld.%ld:%ld",
				(0xff & (server.sin_addr.s_addr >> 24)),
				(0xff & (server.sin_addr.s_addr >> 16)),
				(0xff & (server.sin_addr.s_addr >> 8)),
				(0xff & server.sin_addr.s_addr), htons(server.sin_port));
			error = ERR_BIND;
			break;
		}

		//Listen
		if (listen(acceptSock, listenBacklog) < 0) {
			logme(L_ERROR, "can't listen on socket %ld backlog %ld", acceptSock, listenBacklog);
			error = ERR_LISTEN_SOCKET;
			break;
		}
#if BEBBOSSH_AROS
		{
			long flags = 1;
			IoctlSocket(acceptSock, FIONBIO, (char *)&flags);
		}
#endif
#if BEBBOSSH_AROS
		logme(L_DEBUG, "bebbosshd/AROS: listening");
#endif

		//Accept and incoming connection
		logme(L_INFO, "waiting for incoming connections on %ld.%ld.%ld.%ld:%ld",
				(0xff & (server.sin_addr.s_addr >> 24)),
				(0xff & (server.sin_addr.s_addr >> 16)),
				(0xff & (server.sin_addr.s_addr >> 8)),
				(0xff & server.sin_addr.s_addr), htons(server.sin_port));

		for(;;) {
			if (stopped) {
				abortAll();
				pruneDeadClients();
			}

			// terminated
			if (stopped && !timerOn) {
				logme(L_INFO, "exiting main loop");
				break;
			}

			if (stopped && !(++stopped&15)) {
				cancelRunning();
				logme(L_DEBUG, "stopped=%ld", stopped);
			}

			static fd_set readfds;
			FD_ZERO(&readfds);
			int selectMax = acceptSock;

			// accept new until cancel signalled.
			if (!stopped)
				FD_SET(acceptSock, &readfds);

			uint32_t sz = listeners.getMax();
			if (sz) {
				uint32_t n = 0;
				for (uint32_t i = 0; i < sz; ++i) {
					Listener * l = listeners[i];
					if (!l)
						continue;
					// only wait if there is room for data
					logme(L_ULTRA, "waiting for %ld", l->getSockFd());
					if (l->isOpen() && l->isBufferFree()) {
						int fd = l->getSockFd();
						++n;
						FD_SET(fd, &readfds);
						if (fd > selectMax)
							selectMax = fd;
					}
				}
				if (!n)
					pruneDeadClients();
			}

#if BEBBOSSH_AMIGA_API
			ULONG signales = SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_F | portMask | timerMask;
#if BEBBOSSH_AROS && defined(BEBBOSSH_AROS_MINCRT)
			struct timeval waitTimeout;
			waitTimeout.tv_sec = 1;
			waitTimeout.tv_usec = 0;
			select(selectMax + 1, &readfds, NULL, NULL, &waitTimeout);
			signales = 0;
			checkFinished();
#else
			WaitSelect(selectMax + 1, &readfds, NULL, NULL, 0, &signales);
#endif

			logme(L_ULTRA, "got signal mask %08lX", signales);

			if (signales & SIGBREAKF_CTRL_C) {
				logme(L_INFO, "got CTRL-C, attempt to exit");
				stopped = 1;
			}

			if (signales & SIGBREAKF_CTRL_F) {
				checkFinished();
			}

			if (signales & timerMask) {
				logme(L_ULTRA, "*** beep *** TIMER *** beep ***");
				// never reply to...
				GetMsg(timerPort);
				timerOn = false;

				timeoutWaitForChar();

				if (noopMask)
					sendNoop();
			}
			if (clients.getCount() && !timerOn)
				startTimer();

			if (signales & portMask) {
				struct Message *msg = GetMsg(port);
				handleMsg(msg);
			}
#else
			int sn = listeners.getMax();
			if (sn < acceptSock) sn = acceptSock;

			uint32_t csz = clients.getMax();
#if BEBBOSSH_POSIX_SHELL
			for (int i = 0; i < csz; ++i) {
				auto c = clients[i];
				if (c) {
					int h = c->getHandle();
					if (h) {
						FD_SET(h, &readfds);
						if (h > sn)
							sn = h;
					}
				}
			}
#endif
			select(sn + 1, &readfds, NULL, NULL, 0);
#endif

			// handle new connections
			if (FD_ISSET(acceptSock, &readfds)) {
				int accepted = 0;
				for (;;) {
					struct sockaddr_in peer;
					socklen_t peerLen = sizeof(peer);
					int clientFds = accept(acceptSock, (struct sockaddr* )&peer, &peerLen);
					if (clientFds < 0) {
						int err = Errno();
						if (accepted
#ifdef EWOULDBLOCK
							|| err == EWOULDBLOCK
#endif
							|| err == EAGAIN) {
							break;
						}
						logme(L_DEBUG, "Socket shutdown for %ld errno=%ld", acceptSock, err);
						stopped = 1;
						break;
					}

					logme(L_INFO, "new connection from %ld.%ld.%ld.%ld:%ld on socket %ld",
							(0xff & (peer.sin_addr.s_addr >> 24)),
							(0xff & (peer.sin_addr.s_addr >> 16)),
							(0xff & (peer.sin_addr.s_addr >> 8)),
							(0xff & peer.sin_addr.s_addr), peer.sin_port, clientFds);
					SshSession *cs = new SshSession(clientFds);
					if (!cs) {
						CloseSocket(clientFds);
					} else {

						if (clients[clientFds] || listeners[clientFds]) {
							auto c1 = listeners.remove(clientFds);
							auto c2 = clients.remove(clientFds);
							logme(L_INFO, "removing client connection for old socket %ld", clientFds);
							delete (c1 ? c1 : c2);
						}

						clients.add(clientFds, cs);
						listeners.add(clientFds, cs);
						cs->start();
					}

					++accepted;
					if (accepted >= BEBBOSSH_ACCEPT_BURST)
						break;
				}
				if (accepted)
					continue;
			}

#if BEBBOSSH_POSIX_SHELL
			for (int i = 0; i < csz; ++i) {
				auto c = clients[i];
				if (c) {
					int h = c->getHandle();
					if (h && FD_ISSET(h, &readfds)) {
						if (c->readHandle() < 0) {
							c->close();
						}
					}
				}
			}
#endif

			sz = listeners.getMax();
			bool somethingClosed = false;
			for (uint32_t i = 0; i < sz; ++i) {
				Listener *l = listeners[i];
				if (!l)
					continue;

				if (FD_ISSET(l->getSockFd(), &readfds)) {
		 			//Receive a message from server
					int readSize = recv(l->getSockFd(), theBuffer, CHUNKSIZE, 0);
					logme(L_FINE, "read %ld from fd=%ld", readSize, l->getSockFd());

					if (readSize > 0) {
						if (!l->processSocketData(theBuffer, readSize)) {
							l->close();
							somethingClosed = true;
							break; //??
						}
					} else {
						l->close();
						somethingClosed = true;
					}
				}
			}
			if (somethingClosed)
				pruneDeadClients();
		}

	} while (0);

	return error;
}
