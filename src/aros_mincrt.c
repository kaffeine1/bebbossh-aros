#if defined(__AROS__)

#include <stddef.h>
#include <time.h>
#include <sys/time.h>

#include <dos/dos.h>
#include <exec/memory.h>
#include <exec/types.h>
#include <aros/symbolsets.h>
#include <proto/dos.h>
#include <proto/exec.h>

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

void *malloc(size_t size)
{
    return AllocVec(size ? size : 1, MEMF_ANY);
}

void free(void *ptr)
{
    if (ptr)
        FreeVec(ptr);
}

int puts(const char *s)
{
    Printf("%s\n", s ? s : "");
    return 0;
}

time_t time(time_t *out)
{
    struct DateStamp ds;
    time_t value;

    DateStamp(&ds);
    value = (time_t)(((ds.ds_Days + 2922) * 1440 + ds.ds_Minute) * 60 +
                     ds.ds_Tick / TICKS_PER_SECOND);
    if (out)
        *out = value;
    return value;
}

clock_t clock(void)
{
    struct DateStamp ds;

    DateStamp(&ds);
    return (clock_t)(((ds.ds_Days * 1440 + ds.ds_Minute) * 60 *
                      TICKS_PER_SECOND) + ds.ds_Tick);
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    struct DateStamp ds;

    (void)tz;
    if (!tv)
        return -1;

    DateStamp(&ds);
    tv->tv_sec = (ds.ds_Days + 2922) * 1440 * 60 +
                 ds.ds_Minute * 60 + ds.ds_Tick / TICKS_PER_SECOND;
    tv->tv_usec = (ds.ds_Tick % TICKS_PER_SECOND) * 20000;
    return 0;
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
