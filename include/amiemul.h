#ifndef __AMIEMUL_H__
#define __AMIEMUL_H__

/*
 * AmigaSSH - amiga emulation code
 *
 * Copyright (C) 2024-2025  Stefan Franke <stefan@franke.ms>
 *
 * GPLv3+ (see project license header)
 */

#ifndef __AMIGA__
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#ifdef __unix__
  #include <unistd.h>
  #include <termios.h>
  #include <sys/ioctl.h>
  #include <sys/types.h>
  #include <sys/socket.h>
#endif

#ifdef _WIN32
  #include <winsock2.h>
  #include <windows.h>
  #include <io.h>
#endif

typedef unsigned long ULONG;
typedef FILE * BPTR;
typedef char * STRPTR;

/* File open modes */
#define MODE_OLDFILE    "rb"
#define MODE_NEWFILE    "wb"
#define MODE_READWRITE  "ab+"

static inline BPTR Open(const char *n, const char *m) {
    BPTR f = fopen(n, m);
    if (!f) return NULL;
    if (m[0] == 'a') fseek(f, 0, SEEK_SET);
    return f;
}

#define OFFSET_END       SEEK_END
#define OFFSET_CURRENT   SEEK_CUR
#define OFFSET_BEGINNING SEEK_SET

static inline long Seek(FILE *f, long offset, int whence) {
    // get current position before seeking
    long pos_before = ftell(f);
    if (pos_before == -1L) {
        return -1L; // error
    }

    // perform the seek
    if (fseek(f, offset, whence) != 0) {
        return -1L; // error
    }

    // return the position before the seek
    return pos_before;
}

/* Directory lock struct */
/* Directory lock struct */
typedef struct DirInfoBlock {
    DIR  *dir;
    char  path[PATH_MAX];

    // constructor
    DirInfoBlock(DIR *d = nullptr, const char *p = nullptr)
        : dir(d) {
        if (p) {
            strncpy(path, p, PATH_MAX - 1);
            path[PATH_MAX - 1] = '\0'; // ensure null termination
        } else {
            path[0] = '\0';
        }
    }

    // assignment from DIR* (reset state)
    DirInfoBlock &operator=(DIR *x) {
        dir = x;
        if (!x) {
            path[0] = '\0';
        }
        return *this;
    }

    // truthiness check
    operator bool() const {
        return dir != nullptr;
    }

    // helper: return stored path
    const char *getPath() const {
        return path;
    }

    // helper: close directory
    void close() {
        if (dir) {
            closedir(dir);
            dir = nullptr;
        }
        path[0] = '\0';
    }
} DPTR;

/* Use DPTR (DirInfoBlock) in NameFromLock */
static inline int NameFromLock(DPTR &lock, char *buf, size_t size) {
    if (!lock) {
        // no valid directory lock
        if (size > 0) buf[0] = '\0';
        return 0;
    }
    // copy stored path into buffer
    strncpy(buf, lock.path, size - 1);
    buf[size - 1] = '\0'; // ensure null termination
    return 1;
}

/* Lock / UnLock */
#define SHARED_LOCK 0
static inline DPTR Lock(const char *path, int mode) {
    (void)mode;
    DPTR lock = {0, 0};
    DIR *d = opendir(path);
    if (!d) {
        lock.dir = NULL;
        lock.path[0] = '\0';
        return lock;
    }
    lock.dir = d;
    strncpy(lock.path, path, PATH_MAX);
    lock.path[PATH_MAX-1] = '\0';
    return lock;
}

static inline void UnLock(DPTR lock) {
    if (lock.dir) closedir(lock.dir);
}

/* FileInfoBlock */
struct FileInfoBlock {
    struct stat st;
    char fib_FileName[NAME_MAX+1];
    char fib_DirPath[PATH_MAX];
};

/* File lock/type */
typedef FILE * BPTR;
typedef const char * FPTR;
static inline FPTR LockF(const char *path, char const * mode) { (void)mode; return path; }
static inline void UnLockF(FPTR lock) { (void)lock; }

/* Macros */
#define IS_FILE(fib) (!S_ISDIR((fib).st.st_mode))
#define IS_DIR(fib)   (S_ISDIR((fib).st.st_mode))
#define IS_LINK(fib)  (S_ISLNK((fib).st.st_mode))

#define fib_Size       st.st_size
#define fib_Protection st.st_mode
#define fib_Date       st.st_mtime
#define DateStamp      timespec

#define fib_OwnerUID       st.st_uid
#define fib_OwnerGID       st.st_gid
#define fib_DirEntryType   st.st_mode   /* use S_ISDIR/S_ISREG/S_ISLNK macros to interpret */
#define fib_NumBlocks      st.st_blocks /* number of 512-byte blocks allocated */
#define fib_EntryType      st.st_mode   /* same as DirEntryType, for compatibility */

#define fib_DiskKey     st.st_ino

/* Examine: first entry */
static inline int Examine(DPTR & lock, FileInfoBlock *fib) {
    if (!lock.dir || !fib) return 0;
    rewinddir(lock.dir);
    struct dirent *de = readdir(lock.dir);
    if (!de) return 0;
    strncpy(fib->fib_FileName, de->d_name, NAME_MAX);
    fib->fib_FileName[NAME_MAX] = '\0';
    strncpy(fib->fib_DirPath, lock.path, PATH_MAX);
    fib->fib_DirPath[PATH_MAX-1] = '\0';
    char fullpath[PATH_MAX];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", fib->fib_DirPath, fib->fib_FileName);
    if (lstat(fullpath, &fib->st) == -1) return 0;
    return 1;
}

static inline int ExamineF(FPTR lock, struct FileInfoBlock *fib) {
    if (!lock || !fib) return 0;

    // basename
    const char *base = strrchr(lock, '/');
#ifdef _WIN32
    if (!base) base = strrchr(lock, '\\');
#endif
    if (base) base++; else base = lock;

    strncpy(fib->fib_FileName, base, NAME_MAX);
    fib->fib_FileName[NAME_MAX] = '\0';

    // full path
    strncpy(fib->fib_DirPath, lock, PATH_MAX);
    fib->fib_DirPath[PATH_MAX-1] = '\0';

    if (lstat(lock, &fib->st) == -1) return 0;
    return 1;
}


/* ExNext: subsequent entries */
static inline int ExNext(DPTR & lock, FileInfoBlock *fib) {
    if (!lock.dir || !fib) return 0;
    struct dirent *de = readdir(lock.dir);
    if (!de) return 0;
    strncpy(fib->fib_FileName, de->d_name, NAME_MAX);
    fib->fib_FileName[NAME_MAX] = '\0';
    strncpy(fib->fib_DirPath, lock.path, PATH_MAX);
    fib->fib_DirPath[PATH_MAX-1] = '\0';
    char fullpath[PATH_MAX];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", fib->fib_DirPath, fib->fib_FileName);
    if (lstat(fullpath, &fib->st) == -1) return 0;
    return 1;
}

/* CreateDir */
static inline DPTR CreateDir(const char *path) {
    if (mkdir(path, 0777) == -1) {
        struct stat st;
        if (stat(path, &st) == -1 || !S_ISDIR(st.st_mode)) return DPTR(0,0);
    }
    return Lock(path, SHARED_LOCK);
}

/* Protection */
#define SetProtection(path, mask) chmod((path), (mask))

#ifndef FNM_IGNORECASE
#define FNM_IGNORECASE 0
#endif

/* I/O */
#define Read(f,b,s)      fread((b), 1, (s), (f))
#define Write(f,b,s)     fwrite((b), 1, (s), (f))
#define Close(f)         fclose(f)

/* Amiga DeleteFile() -> POSIX unlink() */
#define DeleteFile(path)   (unlink(path) == 0)

#define AllocVec(s,t)    malloc(s)
#define FreeVec(p)       free(p)
extern "C" { void free(void *);}

/* Socket handling */
#ifdef __unix__
  #define CloseSocket(s)     ::close(s)
  #define IoctlSocket(s,f,p) ioctl((s),(f),(p))
#elif defined(_WIN32)
  #define CloseSocket(s)     closesocket(s)
  #define IoctlSocket(s,f,p) ioctlsocket((s),(f),(p))
#endif

#define IsInteractive(f) isatty(fileno(f))
static inline int Errno(void) { return errno; }

#ifdef __unix__
  #define Delay(n) usleep((n) * 20000)
#elif defined(_WIN32)
  #define Delay(n) Sleep((n) * 20)
#endif

#define __stdargs
#define __far

/* utoa */
static inline char *utoa(unsigned int value, char *buf, int base) {
    static const char digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char tmp[32]; int i = 0;
    if (base < 2 || base > 36) { buf[0] = '\0'; return buf; }
    do { tmp[i++] = digits[value % base]; value /= base; } while (value && i < (int)sizeof(tmp));
    int j = 0; while (i--) buf[j++] = tmp[i]; buf[j] = '\0'; return buf;
}

/* FGets */
static inline char *FGets(FILE *file, char *buf, int len) {
    char *s = fgets(buf, len, file);
    if (s) { size_t l = strlen(s); if (l && s[l-1] == '\n') s[l-1] = '\0'; }
    return s;
}

#define FPuts(f,s) fputs(s,f);fflush(f)

#define gets(a,b) FGets(stdin,a,b)

/* Case-insensitive compare */
#ifdef _WIN32
  #define stricmp  _stricmp
  #define strnicmp _strnicmp
#else
  #include <strings.h>
  #define stricmp  strcasecmp
  #define strnicmp strncasecmp
#endif

extern "C" char* concat(const char *s0, ...);

#define DateStampF(pnow) clock_gettime(CLOCK_REALTIME, pnow)
#define DateStamp timespec


static inline long delta_ms(const DateStamp &now, const DateStamp &then) {
    time_t sec_diff  = now.tv_sec  - then.tv_sec;
    long   nsec_diff = now.tv_nsec - then.tv_nsec;

    // normalize if nanoseconds went negative
    if (nsec_diff < 0) {
        sec_diff--;
        nsec_diff += 1000000000L;
    }

    return sec_diff * 1000L + nsec_diff / 1000000L;
}

#define DOSTRUE (-1L)
#define DOSFALSE (0)

/**
 * WaitForChar - check if input is available on a file descriptor
 * @fd: file descriptor (e.g. STDIN_FILENO)
 * @ticks: timeout in "ticks" (Amiga style, 1 tick = 20 ms)
 *
 * Returns DOSTRUE (1) if input is ready, DOSFALSE (0) otherwise.
 */
static inline int WaitForChar(BPTR in, int ticks) {
    fd_set set;
    struct timeval timeout;

    int fd = fileno(in);

    FD_ZERO(&set);
    FD_SET(fd, &set);

    // convert ticks (20 ms each) to timeval
    long usec = ticks * 20000; // 20,000 µs per tick
    timeout.tv_sec  = usec / 1000000;
    timeout.tv_usec = usec % 1000000;

    int rv = select(fd + 1, &set, NULL, NULL, &timeout);
    if (rv > 0 && FD_ISSET(fd, &set))
        return DOSTRUE;
    return DOSFALSE;
}

/* Amiga MakeLink() -> POSIX symlink() */
#define LINK_SOFT   0   /* symbolic link */
#define LINK_HARD   1   /* hard link (Amiga style) */

static inline int MakeLink(const char *to, size_t itarget, int type) {
	const char * target = (char const *)itarget;
    if (type == LINK_SOFT) {
        // symbolic link
        return symlink(target, to) == 0;
    } else if (type == LINK_HARD) {
        // hard link
        return link(target, to) == 0;
    }
    return 0; // unsupported type
}

static inline int Rename(const char *from, const char *to) {
    // return 1 on success, 0 on failure (Amiga style)
    return (rename(from, to) == 0);
}

#include <pthread.h>

static inline void InitSemaphore(pthread_mutex_t *sem) {
    pthread_mutex_init(sem, NULL);
}

static inline void ObtainSemaphore(pthread_mutex_t *sem) {
    pthread_mutex_lock(sem);
}

static inline void ReleaseSemaphore(pthread_mutex_t *sem) {
    pthread_mutex_unlock(sem);
}
#endif /* !__AMIGA__ */
#endif /* __AMIEMUL_H__ */
