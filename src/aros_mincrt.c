#if defined(__AROS__)

#include <stddef.h>
#include <stdarg.h>
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

void *malloc(size_t size)
{
    size_t total = (size ? size : 1) + sizeof(size_t);
    size_t *mem = (size_t *)AllocVec(total, MEMF_ANY);

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
    if (ptr)
        FreeVec(((size_t *)ptr) - 1);
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
    PutStr(buf);
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
    PutStr(s ? s : "");
    PutStr("\n");
    return 0;
}

void *__stdio_getstdout(void)
{
    return 0;
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
