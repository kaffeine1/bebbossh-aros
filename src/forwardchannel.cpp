/*
 *      Author: Stefan "Bebbo"Franke
 */
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <netdb.h>
#include <forwardchannel.h>
#include "platform.h"
#if BEBBOSSH_AMIGA_API
#include <proto/exec.h>
#include <proto/socket.h>

extern struct SignalSemaphore theLock;

#else
#include "amiemul.h"

extern pthread_mutex_t theLock;

#endif
#include <sshsession.h>
#include "channel.h"
#include "log.h"

extern Stack<Listener> *listenersPtr;
#define listeners (*listenersPtr)

ForwardChannel::ForwardChannel(SshSession * server, uint32_t channel)
: Channel(server, channel, C_FORWARD), listener(this)
{
	memset(&sinLocal, 0, sizeof(sinLocal));
	memset(&sinRemote, 0, sizeof(sinRemote));
}

ForwardChannel::~ForwardChannel() {
}

void ForwardChannel::abort() {
	listener.close();
}

bool ForwardChannel::init(uint8_t * src, uint32_t srcPort, uint8_t * to, uint32_t toPort) {
	logme(L_TRACE, "@%ld:%ld from %s:%ld to %s:%ld", server->getSockFd(), channel, src, srcPort, to, toPort);
	struct hostent *host = gethostbyname((char *)to);
	if (0 == host)
		return false;

	listener.setSockFd(socket(AF_INET, SOCK_STREAM, 0));
	if (listener.getSockFd() < 0)
		return false;

	// bind to a local port before connecting
	sinLocal.sin_family = AF_INET;
	sinLocal.sin_addr.s_addr = INADDR_ANY;

	logme(L_TRACE, "@%ld:%ld binding on %ld.%ld.%ld.%ld:%ld", server->getSockFd(), channel,
			(0xff & (sinLocal.sin_addr.s_addr >> 24)),
			(0xff & (sinLocal.sin_addr.s_addr >> 16)),
			(0xff & (sinLocal.sin_addr.s_addr >> 8)),
			(0xff & sinLocal.sin_addr.s_addr), sinLocal.sin_port);

	if (bind(listener.getSockFd(), (struct sockaddr *)&sinLocal, sizeof(sinLocal)))
		return false;

	sinRemote.sin_family = host->h_addrtype;
	sinRemote.sin_port = toPort;
	sinRemote.sin_addr.s_addr = getInt32(host->h_addr);

	logme(L_INFO, "@%ld:%ld connecting %ld to %ld.%ld.%ld.%ld:%ld", server->getSockFd(), channel, listener.getSockFd(),
			(0xff & (sinRemote.sin_addr.s_addr >> 24)),
			(0xff & (sinRemote.sin_addr.s_addr >> 16)),
			(0xff & (sinRemote.sin_addr.s_addr >> 8)),
			(0xff & sinRemote.sin_addr.s_addr), sinRemote.sin_port);

	if (0 != connect(listener.getSockFd(), (struct sockaddr* )&sinRemote, sizeof(sinRemote)))
		return false;

	return true;
}

int ForwardChannel::processSocketData(void * data, int len) {
	logme(L_FINE, "@%ld:%ld receiving %ld bytes", server->getSockFd(), channel, len);
	return server->channelWrite(channel, data, len);
}

int ForwardChannel::handleData(char * data, unsigned len) {
	if (!listener.isOpen())
		return -1;

	logme(L_FINE, "@%ld:%ld forwarded %ld bytes", server->getSockFd(), channel, len);
	return mysend(listener.getSockFd(), data, len) ? 0 : -1;
}

ForwardListener::ForwardListener(ForwardChannel * fwc_)
: fwc(fwc_) {
}

ForwardListener::~ForwardListener() {}

bool ForwardListener::isBufferFree() const {
	return true;
}

int ForwardListener::processSocketData(void * data, int len) {
	return fwc->processSocketData(data, len);
}

void ForwardListener::close() {
	if (open) {
		logme(L_DEBUG, "closing socket %ld", sockFd);
		CloseSocket(sockFd);
		open = false;
	}
	ObtainSemaphore(&theLock);
	listeners.remove(sockFd);
	ReleaseSemaphore(&theLock);

	fwc->closeChannel();
}
