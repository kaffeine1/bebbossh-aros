#ifndef BEBBOSSH_AROS_MINCRT_WRAPPERS_H
#define BEBBOSSH_AROS_MINCRT_WRAPPERS_H

#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT)

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/semaphores.h>
#include <exec/tasks.h>
#include <dos/dos.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <utility/tagitem.h>

extern struct Library *SocketBase;

#ifdef __cplusplus
extern "C" {
#endif

int bebbossh_aros_socket(struct Library *base, int domain, int type, int protocol);
int bebbossh_aros_bind(struct Library *base, int s, struct sockaddr *name, socklen_t namelen);
int bebbossh_aros_listen(struct Library *base, int s, int backlog);
int bebbossh_aros_accept(struct Library *base, int s, struct sockaddr *addr, socklen_t *addrlen);
int bebbossh_aros_connect(struct Library *base, int s, struct sockaddr *name, socklen_t namelen);
int bebbossh_aros_send(struct Library *base, int s, const void *msg, int len, int flags);
int bebbossh_aros_recv(struct Library *base, int s, void *buf, int len, int flags);
int bebbossh_aros_shutdown(struct Library *base, int s, int how);
int bebbossh_aros_ioctl_socket(struct Library *base, int s, unsigned long request, char *argp);
int bebbossh_aros_close_socket(struct Library *base, int s);
int bebbossh_aros_wait_select(struct Library *base, int nfds, fd_set *readfds, fd_set *writefds,
                              fd_set *exceptfds, struct timeval *timeout, ULONG *sigmask);
ULONG bebbossh_aros_socket_base_tag_list(struct Library *base, struct TagItem *tags);
void bebbossh_aros_delay(ULONG ticks);
void bebbossh_aros_datestamp(struct DateStamp *ds);
void bebbossh_aros_signal(struct Task *task, ULONG signalSet);
void bebbossh_aros_init_semaphore(struct SignalSemaphore *sigSem);
void bebbossh_aros_obtain_semaphore(struct SignalSemaphore *sigSem);
void bebbossh_aros_release_semaphore(struct SignalSemaphore *sigSem);

#ifdef __cplusplus
}
#endif

#undef socket
#undef bind
#undef listen
#undef accept
#undef connect
#undef send
#undef recv
#undef shutdown
#undef IoctlSocket
	#undef CloseSocket
	#undef WaitSelect
	#undef Delay
	#undef DateStamp
	#undef Signal
#undef InitSemaphore
#undef ObtainSemaphore
#undef ReleaseSemaphore

#define socket(domain, type, protocol) bebbossh_aros_socket(SocketBase, (domain), (type), (protocol))
#define bind(s, name, namelen) bebbossh_aros_bind(SocketBase, (s), (name), (namelen))
#define listen(s, backlog) bebbossh_aros_listen(SocketBase, (s), (backlog))
#define accept(s, addr, addrlen) bebbossh_aros_accept(SocketBase, (s), (addr), (addrlen))
#define connect(s, name, namelen) bebbossh_aros_connect(SocketBase, (s), (name), (namelen))
#define send(s, msg, len, flags) bebbossh_aros_send(SocketBase, (s), (msg), (len), (flags))
#define recv(s, buf, len, flags) bebbossh_aros_recv(SocketBase, (s), (buf), (len), (flags))
#define shutdown(s, how) bebbossh_aros_shutdown(SocketBase, (s), (how))
#define IoctlSocket(s, request, argp) bebbossh_aros_ioctl_socket(SocketBase, (s), (request), (argp))
#define CloseSocket(s) bebbossh_aros_close_socket(SocketBase, (s))
	#define WaitSelect(nfds, readfds, writefds, exceptfds, timeout, sigmask) \
		bebbossh_aros_wait_select(SocketBase, (nfds), (readfds), (writefds), (exceptfds), (timeout), (sigmask))
	#define Delay(ticks) bebbossh_aros_delay((ticks))
	#define DateStamp(ds) bebbossh_aros_datestamp((ds))
#define Signal(task, signalSet) bebbossh_aros_signal((task), (signalSet))
#define InitSemaphore(sigSem) bebbossh_aros_init_semaphore((sigSem))
#define ObtainSemaphore(sigSem) bebbossh_aros_obtain_semaphore((sigSem))
#define ReleaseSemaphore(sigSem) bebbossh_aros_release_semaphore((sigSem))

#endif

#endif
