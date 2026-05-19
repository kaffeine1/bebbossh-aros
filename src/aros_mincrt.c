#if defined(__AROS__)

#include <stddef.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <dos/dos.h>
#include <exec/io.h>
#include <exec/libraries.h>
#include <exec/memory.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <exec/tasks.h>
#include <exec/types.h>
#include <aros/libcall.h>
#include <aros/symbolsets.h>
#include <proto/dos.h>
#include <proto/exec.h>
#include <utility/tagitem.h>

char *__argstr;
ULONG __argsize;
char **__argv;
int __argc;
LONG __startup_error;
int __nocommandline = 1;

static char arg_storage[512];
static char *arg_vector[32];
void ___startup_entries_next(struct ExecBase *SysBase);

static void parse_commandline(struct ExecBase *sysBase)
{
    char *in = __argstr ? __argstr : "";
    char *out = arg_storage;
    size_t left = sizeof(arg_storage) - 1;
    int argc = 0;

    (void)sysBase;
    arg_vector[argc++] = (char *)"bebbosshkeygen";
    while (*in && argc < (int)(sizeof(arg_vector) / sizeof(arg_vector[0])) - 1) {
        while (*in == ' ' || *in == '\t' || *in == '\n' || *in == '\r')
            ++in;
        if (!*in)
            break;
        arg_vector[argc++] = out;
        if (*in == '"') {
            ++in;
            while (*in && *in != '"' && left) {
                *out++ = *in++;
                --left;
            }
            if (*in == '"')
                ++in;
        } else {
            while (*in && *in != ' ' && *in != '\t' && *in != '\n' && *in != '\r' && left) {
                *out++ = *in++;
                --left;
            }
        }
        if (left) {
            *out++ = 0;
            --left;
        }
    }
    *out = 0;
    arg_vector[argc] = NULL;
    __argc = argc;
    __argv = arg_vector;
    ___startup_entries_next(sysBase);
}

ADD2SET(parse_commandline, PROGRAM_ENTRIES, -125)

void *memset(void *ptr, int value, size_t len)
{
    unsigned char *p = (unsigned char *)ptr;
    while (len--)
        *p++ = (unsigned char)value;
    return ptr;
}

void *memcpy(void *dst, const void *src, size_t len)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (len--)
        *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t len)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || !len)
        return dst;
    if (d < s) {
        while (len--)
            *d++ = *s++;
    } else {
        d += len;
        s += len;
        while (len--)
            *--d = *--s;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t len)
{
    const unsigned char *p = (const unsigned char *)a;
    const unsigned char *q = (const unsigned char *)b;
    while (len--) {
        if (*p != *q)
            return (int)*p - (int)*q;
        ++p;
        ++q;
    }
    return 0;
}

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p)
        ++p;
    return (size_t)(p - s);
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t len)
{
    if (!len)
        return 0;
    while (--len && *a && *a == *b) {
        ++a;
        ++b;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static int lower_ascii(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

int strcasecmp(const char *a, const char *b)
{
    int ca;
    int cb;

    do {
        ca = lower_ascii((unsigned char)*a++);
        cb = lower_ascii((unsigned char)*b++);
        if (ca != cb)
            return ca - cb;
    } while (ca);
    return 0;
}

char *strcpy(char *dst, const char *src)
{
    char *out = dst;
    while ((*dst++ = *src++))
        ;
    return out;
}

char *strncpy(char *dst, const char *src, size_t len)
{
    char *out = dst;
    while (len && *src) {
        *dst++ = *src++;
        --len;
    }
    while (len--) {
        *dst++ = 0;
    }
    return out;
}

char *strcat(char *dst, const char *src)
{
    strcpy(dst + strlen(dst), src);
    return dst;
}

char *strchr(const char *s, int c)
{
    char ch = (char)c;
    do {
        if (*s == ch)
            return (char *)s;
    } while (*s++);
    return NULL;
}

char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    char ch = (char)c;
    do {
        if (*s == ch)
            last = s;
    } while (*s++);
    return (char *)last;
}

char *strpbrk(const char *s, const char *accept)
{
    while (*s) {
        const char *a = accept;
        while (*a) {
            if (*s == *a++)
                return (char *)s;
        }
        ++s;
    }
    return NULL;
}

char *strstr(const char *s, const char *find)
{
    size_t len;

    if (!*find)
        return (char *)s;
    len = strlen(find);
    while (*s) {
        if (*s == *find && strncmp(s, find, len) == 0)
            return (char *)s;
        ++s;
    }
    return NULL;
}

int strncasecmp(const char *a, const char *b, size_t len)
{
    int ca;
    int cb;

    if (!len)
        return 0;
    do {
        ca = lower_ascii((unsigned char)*a++);
        cb = lower_ascii((unsigned char)*b++);
        if (ca != cb)
            return ca - cb;
    } while (ca && --len);
    return 0;
}

#if defined(__x86_64__)
static APTR bebbossh_aros_exec_allocvec(IPTR byteSize, ULONG requirements)
{
    APTR base = SysBase;
    APTR func = __AROS_GETVECADDR(base, 114);
    APTR save;
    APTR ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((APTR (*)(IPTR, ULONG))func)(byteSize, requirements);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
}

static void bebbossh_aros_exec_freevec(APTR memoryBlock)
{
    APTR base = SysBase;
    APTR func = __AROS_GETVECADDR(base, 115);
    APTR save;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ((void (*)(APTR))func)(memoryBlock);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
}
#endif

APTR bebbossh_aros_allocvec(IPTR byteSize, ULONG requirements)
{
#if defined(__x86_64__)
    return bebbossh_aros_exec_allocvec(byteSize, requirements);
#else
    return AllocVec(byteSize, requirements);
#endif
}

void bebbossh_aros_freevec(APTR memoryBlock)
{
#if defined(__x86_64__)
    if (memoryBlock)
        bebbossh_aros_exec_freevec(memoryBlock);
#else
    if (memoryBlock)
        FreeVec(memoryBlock);
#endif
}

struct MsgPort *bebbossh_aros_create_msgport(void)
{
#if defined(__x86_64__)
    APTR base = SysBase;
    APTR func = __AROS_GETVECADDR(base, 111);
    APTR save;
    struct MsgPort *ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((struct MsgPort *(*)(void))func)();
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return CreateMsgPort();
#endif
}

void bebbossh_aros_delete_msgport(struct MsgPort *port)
{
#if defined(__x86_64__)
    if (port) {
        APTR base = SysBase;
        APTR func = __AROS_GETVECADDR(base, 112);
        APTR save;

        __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                             : "=&rm"(save) : "rm"(base) : "r12");
        ((void (*)(struct MsgPort *))func)(port);
        __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    }
#else
    if (port)
        DeleteMsgPort(port);
#endif
}

APTR bebbossh_aros_create_iorequest(struct MsgPort *replyPort, ULONG size)
{
#if defined(__x86_64__)
    APTR base = SysBase;
    APTR func = __AROS_GETVECADDR(base, 109);
    APTR save;
    APTR ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((APTR (*)(struct MsgPort *, ULONG))func)(replyPort, size);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return CreateIORequest(replyPort, size);
#endif
}

void bebbossh_aros_delete_iorequest(APTR request)
{
#if defined(__x86_64__)
    if (request) {
        APTR base = SysBase;
        APTR func = __AROS_GETVECADDR(base, 110);
        APTR save;

        __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                             : "=&rm"(save) : "rm"(base) : "r12");
        ((void (*)(APTR))func)(request);
        __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    }
#else
    if (request)
        DeleteIORequest(request);
#endif
}

LONG bebbossh_aros_open_device(const char *name, IPTR unit, struct IORequest *request, ULONG flags)
{
#if defined(__x86_64__)
    APTR base = SysBase;
    APTR func = __AROS_GETVECADDR(base, 74);
    APTR save;
    LONG ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(CONST_STRPTR, IPTR, struct IORequest *, ULONG))func)(name, unit, request, flags);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return OpenDevice(name, unit, request, flags);
#endif
}

void bebbossh_aros_close_device(struct IORequest *request)
{
#if defined(__x86_64__)
    if (request) {
        APTR base = SysBase;
        APTR func = __AROS_GETVECADDR(base, 75);
        APTR save;

        __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                             : "=&rm"(save) : "rm"(base) : "r12");
        ((void (*)(struct IORequest *))func)(request);
        __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    }
#else
    if (request)
        CloseDevice(request);
#endif
}

struct Library *bebbossh_aros_open_library(const char *name, ULONG version)
{
#if defined(__x86_64__)
    APTR base = SysBase;
    APTR func = __AROS_GETVECADDR(base, 92);
    APTR save;
    struct Library *ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((struct Library *(*)(CONST_STRPTR, ULONG))func)(name, version);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return OpenLibrary(name, version);
#endif
}

void bebbossh_aros_close_library(struct Library *library)
{
#if defined(__x86_64__)
    if (library) {
        APTR base = SysBase;
        APTR func = __AROS_GETVECADDR(base, 69);
        APTR save;

        __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                             : "=&rm"(save) : "rm"(base) : "r12");
        ((void (*)(struct Library *))func)(library);
        __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    }
#else
    if (library)
        CloseLibrary(library);
#endif
}

struct Task *bebbossh_aros_find_task(const char *name)
{
#if defined(__x86_64__)
    APTR base = SysBase;
    APTR func = __AROS_GETVECADDR(base, 49);
    APTR save;
    struct Task *ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((struct Task *(*)(CONST_STRPTR))func)(name);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return FindTask(name);
#endif
}

#if defined(__x86_64__)
static APTR bebbossh_aros_libcall_base(struct Library *base, LONG lvo)
{
    return base ? __AROS_GETVECADDR(base, lvo) : 0;
}
#endif

int bebbossh_aros_socket(struct Library *base, int domain, int type, int protocol)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 5);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, int, int))func)(domain, type, protocol);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return socket(domain, type, protocol);
#endif
}

int bebbossh_aros_bind(struct Library *base, int s, struct sockaddr *name, socklen_t namelen)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 6);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, struct sockaddr *, socklen_t))func)(s, name, namelen);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return bind(s, name, namelen);
#endif
}

int bebbossh_aros_listen(struct Library *base, int s, int backlog)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 7);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, int))func)(s, backlog);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return listen(s, backlog);
#endif
}

int bebbossh_aros_accept(struct Library *base, int s, struct sockaddr *addr, socklen_t *addrlen)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 8);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, struct sockaddr *, socklen_t *))func)(s, addr, addrlen);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return accept(s, addr, addrlen);
#endif
}

int bebbossh_aros_connect(struct Library *base, int s, struct sockaddr *name, socklen_t namelen)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 9);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, struct sockaddr *, socklen_t))func)(s, name, namelen);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return connect(s, name, namelen);
#endif
}

int bebbossh_aros_send(struct Library *base, int s, const void *msg, int len, int flags)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 11);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, const void *, int, int))func)(s, msg, len, flags);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return send(s, msg, len, flags);
#endif
}

int bebbossh_aros_recv(struct Library *base, int s, void *buf, int len, int flags)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 13);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, void *, int, int))func)(s, buf, len, flags);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return recv(s, buf, len, flags);
#endif
}

int bebbossh_aros_shutdown(struct Library *base, int s, int how)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 14);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, int))func)(s, how);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return shutdown(s, how);
#endif
}

int bebbossh_aros_errno(struct Library *base)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 27);
    APTR save;
    int ret;
    if (!func)
        return 0;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(void))func)();
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return Errno();
#endif
}

int bebbossh_aros_ioctl_socket(struct Library *base, int s, unsigned long request, char *argp)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 19);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, unsigned long, char *))func)(s, request, argp);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return IoctlSocket(s, request, argp);
#endif
}

int bebbossh_aros_close_socket(struct Library *base, int s)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 20);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int))func)(s);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return CloseSocket(s);
#endif
}

int bebbossh_aros_wait_select(struct Library *base, int nfds, fd_set *readfds, fd_set *writefds,
                              fd_set *exceptfds, struct timeval *timeout, ULONG *sigmask)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 21);
    APTR save;
    int ret;
    if (!func)
        return -1;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *, ULONG *))func)(
        nfds, readfds, writefds, exceptfds, timeout, sigmask);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return WaitSelect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
#endif
}

ULONG bebbossh_aros_socket_base_tag_list(struct Library *base, struct TagItem *tags)
{
#if defined(__x86_64__)
    APTR func = bebbossh_aros_libcall_base(base, 49);
    APTR save;
    ULONG ret;
    if (!func)
        return 0;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((ULONG (*)(struct TagItem *))func)(tags);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return SocketBaseTagList(tags);
#endif
}

void bebbossh_aros_delay(ULONG ticks)
{
#if defined(__x86_64__)
    (void)ticks;
#else
    Delay(ticks);
#endif
}

void bebbossh_aros_datestamp(struct DateStamp *ds)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = base ? __AROS_GETVECADDR(base, 32) : 0;
    APTR save;
    if (!func || !ds)
        return;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12" : "=&rm"(save) : "rm"(base) : "r12");
    ((void (*)(struct DateStamp *))func)(ds);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
#else
    DateStamp(ds);
#endif
}

void bebbossh_aros_signal(struct Task *task, ULONG signalSet)
{
#if defined(__x86_64__)
    (void)task;
    (void)signalSet;
#else
    Signal(task, signalSet);
#endif
}

void bebbossh_aros_init_semaphore(struct SignalSemaphore *sigSem)
{
#if defined(__x86_64__)
    (void)sigSem;
#else
    InitSemaphore(sigSem);
#endif
}

void bebbossh_aros_obtain_semaphore(struct SignalSemaphore *sigSem)
{
#if defined(__x86_64__)
    (void)sigSem;
#else
    ObtainSemaphore(sigSem);
#endif
}

void bebbossh_aros_release_semaphore(struct SignalSemaphore *sigSem)
{
#if defined(__x86_64__)
    (void)sigSem;
#else
    ReleaseSemaphore(sigSem);
#endif
}

void *malloc(size_t size)
{
    size_t total = (size ? size : 1) + sizeof(size_t);
    size_t *mem = (size_t *)bebbossh_aros_allocvec(total, MEMF_ANY);

    if (!mem)
        return NULL;
    *mem = size ? size : 1;
    return mem + 1;
}

void free(void *ptr);

void *realloc(void *ptr, size_t size)
{
    void *next;
    size_t old_size;

    if (!ptr)
        return malloc(size);
    old_size = ((size_t *)ptr)[-1];
    next = malloc(size);
    if (next)
        memcpy(next, ptr, old_size < size ? old_size : size);
    free(ptr);
    return next;
}

void free(void *ptr)
{
    if (ptr) {
        bebbossh_aros_freevec(((size_t *)ptr) - 1);
    }
}

char *strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *copy = (char *)malloc(len);

    if (copy)
        memcpy(copy, s, len);
    return copy;
}

static unsigned long parse_unsigned(const char *s, char **end, int base)
{
    unsigned long value = 0;

    while (*s == ' ' || *s == '\t')
        ++s;
    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
    } else if (base == 0) {
        base = s[0] == '0' ? 8 : 10;
    }
    while (*s) {
        unsigned digit;
        if (*s >= '0' && *s <= '9')
            digit = (unsigned)(*s - '0');
        else if (*s >= 'a' && *s <= 'f')
            digit = (unsigned)(*s - 'a' + 10);
        else if (*s >= 'A' && *s <= 'F')
            digit = (unsigned)(*s - 'A' + 10);
        else
            break;
        if (digit >= (unsigned)base)
            break;
        value = value * (unsigned)base + digit;
        ++s;
    }
    if (end)
        *end = (char *)s;
    return value;
}

unsigned long strtoul(const char *s, char **end, int base)
{
    return parse_unsigned(s, end, base);
}

int atoi(const char *s)
{
    int neg = 0;

    while (*s == ' ' || *s == '\t')
        ++s;
    if (*s == '-') {
        neg = 1;
        ++s;
    }
    return neg ? -(int)parse_unsigned(s, NULL, 10) : (int)parse_unsigned(s, NULL, 10);
}

static unsigned rand_state = 0x12345678u;

int rand(void)
{
    rand_state = rand_state * 1103515245u + 12345u;
    return (int)((rand_state >> 16) & 0x7fff);
}

static void append_char(char **out, size_t *left, int *total, char c)
{
    if (*left > 1) {
        **out = c;
        ++*out;
        --*left;
    }
    ++*total;
}

static void append_string(char **out, size_t *left, int *total, const char *s)
{
    if (!s)
        s = "(null)";
    while (*s)
        append_char(out, left, total, *s++);
}

static void append_number(char **out, size_t *left, int *total, unsigned long value, int neg, unsigned base, int width)
{
    char tmp[32];
    int pos = 0;
    int len;

    do {
        unsigned digit = (unsigned)(value % base);
        tmp[pos++] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
        value /= base;
    } while (value && pos < (int)sizeof(tmp));
    len = pos + (neg ? 1 : 0);
    while (width > len) {
        append_char(out, left, total, ' ');
        --width;
    }
    if (neg)
        append_char(out, left, total, '-');
    while (pos)
        append_char(out, left, total, tmp[--pos]);
}

static int mini_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    char *out = buf;
    size_t left = size;
    int total = 0;

    while (*fmt) {
        int width = 0;
        int longarg = 0;

        if (*fmt != '%') {
            append_char(&out, &left, &total, *fmt++);
            continue;
        }
        ++fmt;
        if (*fmt == '%') {
            append_char(&out, &left, &total, *fmt++);
            continue;
        }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            ++fmt;
        }
        if (*fmt == 'l') {
            longarg = 1;
            ++fmt;
        }
        switch (*fmt++) {
        case 's':
            append_string(&out, &left, &total, va_arg(ap, const char *));
            break;
        case 'c':
            append_char(&out, &left, &total, va_arg(ap, int));
            break;
        case 'd':
        case 'i': {
            long value = longarg ? va_arg(ap, long) : va_arg(ap, int);
            append_number(&out, &left, &total, value < 0 ? (unsigned long)-value : (unsigned long)value, value < 0, 10, width);
            break;
        }
        case 'u':
            append_number(&out, &left, &total, longarg ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int), 0, 10, width);
            break;
        case 'x':
        case 'X':
            append_number(&out, &left, &total, longarg ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int), 0, 16, width);
            break;
        case 'p':
            append_string(&out, &left, &total, "0x");
            append_number(&out, &left, &total, (unsigned long)va_arg(ap, void *), 0, 16, width);
            break;
        default:
            append_char(&out, &left, &total, '?');
            break;
        }
    }
    if (size) {
        if (left)
            *out = 0;
        else
            buf[size - 1] = 0;
    }
    return total;
}

int snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    int rc;

    va_start(ap, fmt);
    rc = mini_vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return rc;
}

int printf(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    int rc;

    va_start(ap, fmt);
    rc = mini_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    Write(Output(), buf, strlen(buf));
    return rc;
}

int putchar(int c)
{
    char ch = (char)c;

    Write(Output(), &ch, 1);
    return c;
}

int puts(const char *s)
{
    if (!s)
        s = "";
    Write(Output(), s, strlen(s));
    Write(Output(), "\n", 1);
    return 0;
}

BPTR bebbossh_aros_open(const char *name, LONG mode)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 5);
    APTR save;
    BPTR ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((BPTR (*)(CONST_STRPTR, LONG))func)(name, mode);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return Open(name, mode);
#endif
}

void bebbossh_aros_close(BPTR file)
{
#if defined(__x86_64__)
    if (file) {
        APTR base = DOSBase;
        APTR func = __AROS_GETVECADDR(base, 6);
        APTR save;

        __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                             : "=&rm"(save) : "rm"(base) : "r12");
        ((BOOL (*)(BPTR))func)(file);
        __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    }
#else
    if (file)
        Close(file);
#endif
}

LONG bebbossh_aros_write(BPTR file, const void *buf, LONG len)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 8);
    APTR save;
    LONG ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(BPTR, const void *, LONG))func)(file, buf, len);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return Write(file, (APTR)buf, len);
#endif
}

LONG bebbossh_aros_read(BPTR file, void *buf, LONG len)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 7);
    APTR save;
    LONG ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(BPTR, void *, LONG))func)(file, buf, len);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return Read(file, buf, len);
#endif
}

LONG bebbossh_aros_seek(BPTR file, LONG offset, LONG mode)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 11);
    APTR save;
    LONG ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(BPTR, LONG, LONG))func)(file, offset, mode);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return Seek(file, offset, mode);
#endif
}

LONG bebbossh_aros_delete_file(const char *name)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 12);
    APTR save;
    LONG ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(CONST_STRPTR))func)(name);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return DeleteFile(name);
#endif
}

LONG bebbossh_aros_rename(const char *oldName, const char *newName)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 13);
    APTR save;
    LONG ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(CONST_STRPTR, CONST_STRPTR))func)(oldName, newName);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return Rename(oldName, newName);
#endif
}

BPTR bebbossh_aros_lock(const char *name, LONG mode)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 14);
    APTR save;
    BPTR ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((BPTR (*)(CONST_STRPTR, LONG))func)(name, mode);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return Lock(name, mode);
#endif
}

void bebbossh_aros_unlock(BPTR lock)
{
#if defined(__x86_64__)
    if (lock) {
        APTR base = DOSBase;
        APTR func = __AROS_GETVECADDR(base, 15);
        APTR save;

        __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                             : "=&rm"(save) : "rm"(base) : "r12");
        ((void (*)(BPTR))func)(lock);
        __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    }
#else
    if (lock)
        UnLock(lock);
#endif
}

LONG bebbossh_aros_examine(BPTR lock, struct FileInfoBlock *fib)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 17);
    APTR save;
    LONG ret;

    if (!lock || !fib)
        return 0;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(BPTR, struct FileInfoBlock *))func)(lock, fib);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return Examine(lock, fib);
#endif
}

LONG bebbossh_aros_exnext(BPTR lock, struct FileInfoBlock *fib)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 18);
    APTR save;
    LONG ret;

    if (!lock || !fib)
        return 0;
    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(BPTR, struct FileInfoBlock *))func)(lock, fib);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return ExNext(lock, fib);
#endif
}

BPTR bebbossh_aros_create_dir(const char *name)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 20);
    APTR save;
    BPTR ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((BPTR (*)(CONST_STRPTR))func)(name);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return CreateDir(name);
#endif
}

LONG bebbossh_aros_ioerr(void)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 22);
    APTR save;
    LONG ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(void))func)();
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return IoErr();
#endif
}

LONG bebbossh_aros_set_protection(const char *name, LONG mask)
{
#if defined(__x86_64__)
    APTR base = DOSBase;
    APTR func = __AROS_GETVECADDR(base, 31);
    APTR save;
    LONG ret;

    __asm__ __volatile__("movq %%r12, %0\n\tmovq %1, %%r12"
                         : "=&rm"(save) : "rm"(base) : "r12");
    ret = ((LONG (*)(CONST_STRPTR, LONG))func)(name, mask);
    __asm__ __volatile__("movq %0, %%r12" : : "rm"(save) : "r12");
    return ret;
#else
    return SetProtection(name, mask);
#endif
}

int fflush(void *stream)
{
    (void)stream;
    return 0;
}

int atexit(void (*fn)(void))
{
    (void)fn;
    return 0;
}

time_t time(time_t *out)
{
    struct DateStamp ds;
    time_t value;

    bebbossh_aros_datestamp(&ds);
    value = (time_t)(((ds.ds_Days + 2922) * 1440 + ds.ds_Minute) * 60 +
                     ds.ds_Tick / TICKS_PER_SECOND);
    if (out)
        *out = value;
    return value;
}

clock_t clock(void)
{
    struct DateStamp ds;

    bebbossh_aros_datestamp(&ds);
    return (clock_t)(((ds.ds_Days * 1440 + ds.ds_Minute) * 60 *
                      TICKS_PER_SECOND) + ds.ds_Tick);
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    struct DateStamp ds;

    (void)tz;
    if (!tv)
        return -1;

    bebbossh_aros_datestamp(&ds);
    tv->tv_sec = (ds.ds_Days + 2922) * 1440 * 60 +
                 ds.ds_Minute * 60 + ds.ds_Tick / TICKS_PER_SECOND;
    tv->tv_usec = (ds.ds_Tick % TICKS_PER_SECOND) * 20000;
    return 0;
}

struct tm *gmtime_r(const time_t *clock, struct tm *result)
{
    time_t t = clock ? *clock : time(NULL);

    memset(result, 0, sizeof(*result));
    result->tm_sec = (int)(t % 60);
    t /= 60;
    result->tm_min = (int)(t % 60);
    t /= 60;
    result->tm_hour = (int)(t % 24);
    result->tm_mday = 1;
    result->tm_mon = 0;
    result->tm_year = 126;
    return result;
}

size_t strftime(char *s, size_t max, const char *format, const struct tm *tm)
{
    (void)format;
    return (size_t)snprintf(s, max, "%02d-Jan-2026 %02d:%02d:%02d",
                            tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
}

int mkdir(const char *path, unsigned mode)
{
    BPTR lock;

    (void)mode;
    lock = CreateDir(path);
    if (!lock)
        return -1;
    UnLock(lock);
    return 0;
}

void exit(int status)
{
    Exit((LONG)status);
    for (;;)
        ;
}

#endif
