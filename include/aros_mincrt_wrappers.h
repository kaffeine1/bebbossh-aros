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
struct hostent;

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
int bebbossh_aros_errno(struct Library *base);
unsigned long bebbossh_aros_inet_addr(struct Library *base, const char *addr);
struct hostent *bebbossh_aros_gethostbyname(struct Library *base, const char *name);
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
struct Library *bebbossh_aros_open_library(const char *name, ULONG version);
void bebbossh_aros_close_library(struct Library *library);
BPTR bebbossh_aros_open(const char *name, LONG mode);
void bebbossh_aros_close(BPTR file);
LONG bebbossh_aros_read(BPTR file, void *buf, LONG len);
LONG bebbossh_aros_write(BPTR file, const void *buf, LONG len);
BPTR bebbossh_aros_input(void);
BPTR bebbossh_aros_output(void);
LONG bebbossh_aros_seek(BPTR file, LONG offset, LONG mode);
LONG bebbossh_aros_delete_file(const char *name);
LONG bebbossh_aros_rename(const char *oldName, const char *newName);
BPTR bebbossh_aros_lock(const char *name, LONG mode);
void bebbossh_aros_unlock(BPTR lock);
LONG bebbossh_aros_examine(BPTR lock, struct FileInfoBlock *fib);
LONG bebbossh_aros_exnext(BPTR lock, struct FileInfoBlock *fib);
BPTR bebbossh_aros_create_dir(const char *name);
BPTR bebbossh_aros_current_dir(BPTR lock);
LONG bebbossh_aros_ioerr(void);
LONG bebbossh_aros_wait_for_char(BPTR file, LONG timeout);
LONG bebbossh_aros_is_interactive(BPTR file);
LONG bebbossh_aros_set_mode(BPTR file, LONG mode);
char *bebbossh_aros_fgets(BPTR file, char *buf, LONG buflen);
LONG bebbossh_aros_name_from_lock(BPTR lock, char *buffer, LONG length);
LONG bebbossh_aros_set_protection(const char *name, LONG mask);
LONG bebbossh_aros_system_tag_list(CONST_STRPTR command, struct TagItem *tags);

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
#undef Errno
#undef inet_addr
#undef gethostbyname
#undef IoctlSocket
#undef CloseSocket
#undef WaitSelect
#undef Delay
#undef DateStamp
#undef Signal
#undef InitSemaphore
#undef ObtainSemaphore
#undef ReleaseSemaphore
#undef OpenLibrary
#undef CloseLibrary
#undef Open
#undef Close
#undef Read
#undef Write
#undef Input
#undef Output
#undef Seek
#undef DeleteFile
#undef Rename
#undef Lock
#undef UnLock
#undef Examine
#undef ExNext
#undef CreateDir
#undef CurrentDir
#undef IoErr
#undef WaitForChar
#undef IsInteractive
#undef SetMode
#undef FGets
#undef NameFromLock
#undef SetProtection

#define socket(domain, type, protocol) bebbossh_aros_socket(SocketBase, (domain), (type), (protocol))
#define bind(s, name, namelen) bebbossh_aros_bind(SocketBase, (s), (name), (namelen))
#define listen(s, backlog) bebbossh_aros_listen(SocketBase, (s), (backlog))
#define accept(s, addr, addrlen) bebbossh_aros_accept(SocketBase, (s), (addr), (addrlen))
#define connect(s, name, namelen) bebbossh_aros_connect(SocketBase, (s), (name), (namelen))
#define send(s, msg, len, flags) bebbossh_aros_send(SocketBase, (s), (msg), (len), (flags))
#define recv(s, buf, len, flags) bebbossh_aros_recv(SocketBase, (s), (buf), (len), (flags))
#define shutdown(s, how) bebbossh_aros_shutdown(SocketBase, (s), (how))
#define Errno() bebbossh_aros_errno(SocketBase)
#define inet_addr(addr) bebbossh_aros_inet_addr(SocketBase, (addr))
#define gethostbyname(name) bebbossh_aros_gethostbyname(SocketBase, (name))
#define IoctlSocket(s, request, argp) bebbossh_aros_ioctl_socket(SocketBase, (s), (request), (char *)(argp))
#define CloseSocket(s) bebbossh_aros_close_socket(SocketBase, (s))
#define WaitSelect(nfds, readfds, writefds, exceptfds, timeout, sigmask) \
	bebbossh_aros_wait_select(SocketBase, (nfds), (readfds), (writefds), (exceptfds), (timeout), (sigmask))
#define Delay(ticks) bebbossh_aros_delay((ticks))
#define DateStamp(ds) bebbossh_aros_datestamp((ds))
#define Signal(task, signalSet) bebbossh_aros_signal((task), (signalSet))
#define InitSemaphore(sigSem) bebbossh_aros_init_semaphore((sigSem))
#define ObtainSemaphore(sigSem) bebbossh_aros_obtain_semaphore((sigSem))
#define ReleaseSemaphore(sigSem) bebbossh_aros_release_semaphore((sigSem))
#define OpenLibrary(name, version) bebbossh_aros_open_library((name), (version))
#define CloseLibrary(library) bebbossh_aros_close_library((library))
#define Open(name, mode) bebbossh_aros_open((name), (mode))
#define Close(file) bebbossh_aros_close((file))
#define Read(file, buf, len) bebbossh_aros_read((file), (buf), (len))
#define Write(file, buf, len) bebbossh_aros_write((file), (buf), (len))
#define Input() bebbossh_aros_input()
#define Output() bebbossh_aros_output()
#define Seek(file, offset, mode) bebbossh_aros_seek((file), (offset), (mode))
#define DeleteFile(name) bebbossh_aros_delete_file((name))
#define Rename(oldName, newName) bebbossh_aros_rename((oldName), (newName))
#define Lock(name, mode) bebbossh_aros_lock((name), (mode))
#define UnLock(lock) bebbossh_aros_unlock((lock))
#define Examine(lock, fib) bebbossh_aros_examine((lock), (fib))
#define ExNext(lock, fib) bebbossh_aros_exnext((lock), (fib))
#define CreateDir(name) bebbossh_aros_create_dir((name))
#define CurrentDir(lock) bebbossh_aros_current_dir((lock))
#define IoErr() bebbossh_aros_ioerr()
#define WaitForChar(file, timeout) bebbossh_aros_wait_for_char((file), (timeout))
#define IsInteractive(file) bebbossh_aros_is_interactive((file))
#define SetMode(file, mode) bebbossh_aros_set_mode((file), (mode))
#define FGets(file, buf, buflen) bebbossh_aros_fgets((file), (buf), (buflen))
#define NameFromLock(lock, buffer, length) bebbossh_aros_name_from_lock((lock), (buffer), (length))
#define SetProtection(name, mask) bebbossh_aros_set_protection((name), (mask))

#endif

#endif
