/*
 * aros_randpool - SHA-512 entropy pool behind randfill() on AROS
 * Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>
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
 *
 * AROS port of the random pool of bebbossh 1.46.1 patch 0008 by Matthias
 * Muench: a 512-bit pool; every call stirs a fresh sample in, output blocks
 * are hashed from the pool and a counter, and the pool is hashed forward after
 * every call, so a later pool does not give away earlier output. A seed file
 * in sshDotDir carries state from run to run.
 *
 * AROS sources instead of the custom chips and the E-clock: the CPU cycle
 * counter (rdtsc, cntvct_el0) timing a walk over 64 KiB, timer.device
 * wake-ups, GetSysTime, DateStamp, the ExecBase dispatch/idle counters,
 * AvailMem (not on x86_64), task and stack addresses.
 *
 * x86_64 (mincrt): no proto/ header is included, so every library call must
 * go through a wrapper of aros_mincrt.c; an unwrapped call does not compile.
 */
#if defined(__AROS__)

#include <stdint.h>
#include <string.h>

#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/io.h>
#include <exec/memory.h>
#include <exec/nodes.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <exec/tasks.h>
#include <devices/timer.h>
#include <dos/dos.h>

#if defined(BEBBOSSH_AROS_MINCRT)
#include "aros_mincrt_wrappers.h"
extern struct ExecBase *SysBase;
#define POOL_CREATE_PORT() bebbossh_aros_create_msgport()
#define POOL_DELETE_PORT(p) bebbossh_aros_delete_msgport((p))
#define POOL_CREATE_IO(p, s) bebbossh_aros_create_iorequest((p), (s))
#define POOL_DELETE_IO(r) bebbossh_aros_delete_iorequest((r))
#define POOL_OPEN_DEVICE(n, u, r, f) bebbossh_aros_open_device((n), (u), (r), (f))
#define POOL_CLOSE_DEVICE(r) bebbossh_aros_close_device((r))
#else
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/timer.h>
/* exec calls, not the amiga.lib CreatePort()/CreateExtIO() (aarch64 clash) */
#define POOL_CREATE_PORT() CreateMsgPort()
#define POOL_DELETE_PORT(p) DeleteMsgPort((p))
#define POOL_CREATE_IO(p, s) CreateIORequest((p), (s))
#define POOL_DELETE_IO(r) DeleteIORequest((struct IORequest *)(r))
#define POOL_OPEN_DEVICE(n, u, r, f) OpenDevice((n), (u), (r), (f))
#define POOL_CLOSE_DEVICE(r) CloseDevice((r))
#endif

#include "sha512.h"
#include "aros_randpool.h"

extern char const *sshDotDir; /* home.cpp: "envarc:.ssh" */

#define POOL_JIT_MEM 65536u  /* walk larger than the L1 data cache */
#define POOL_JIT_STEPS 64u   /* memory updates per sample */
#define POOL_JIT_FIRST 1024u /* first burst, also health checked */
#define POOL_JIT_WAKE 64u    /* burst after each wake-up */
#define POOL_ROUNDS 8u       /* wake-ups at first use, as in 0008 */
#define POOL_WAIT_US 1000u
#ifndef POOL_TIMER_UNIT
#define POOL_TIMER_UNIT UNIT_MICROHZ /* UNIT_VBLANK if MICROHZ misbehaves */
#endif

/* POD statics only: x86_64 runs no global constructors */
static uint8_t pool[64];
static uint64_t outCount;
static uint8_t seeded;
static unsigned poolFlags;
#if !defined(BEBBOSSH_AROS_MINCRT)
static struct SignalSemaphore poolSem;
static volatile uint8_t semReady;
#endif

static inline uint64_t cycles(void) {
#if defined(__i386__) || defined(__x86_64__)
	uint32_t lo, hi;
	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi) : : "memory");
	return ((uint64_t) hi << 32) | lo;
#elif defined(__aarch64__)
	/* generic timer count, readable by AROS tasks (EL1t, cntvoff 0) */
	uint64_t v;
	__asm__ __volatile__("isb\n\tmrs %0, cntvct_el0" : "=r"(v) : : "memory");
	return v;
#else
#error "aros_randpool: no cycle counter for this CPU"
#endif
}

static void wipe(void *p, unsigned n) {
	volatile uint8_t *v = (volatile uint8_t *) p;
	while (n--)
		*v++ = 0;
}

static void be64(uint8_t *p, uint64_t v) {
	for (int i = 7; i >= 0; --i, v >>= 8)
		p[i] = (uint8_t) v;
}

/* out = SHA-512(in[64] | tag[4] | data[len]); out may be in. digestDirect()
   resets only the state and the count, so callers wipe sha afterwards. */
static void poolHash(SHA512 &sha, uint8_t *out, const uint8_t *in, const char *tag,
		const void *data, unsigned len) {
	sha.updateDirect(in, 64);
	sha.updateDirect(tag, 4);
	if (len)
		sha.updateDirect(data, len);
	sha.digestDirect(out);
}

extern "C" void aros_randpool_hash(uint8_t *out, const uint8_t *in, const char *tag,
		const void *data, unsigned len) {
	SHA512 sha;
	poolHash(sha, out, in, tag, data, len);
	wipe(&sha, sizeof(sha));
}

/* CPU jitter: the counter around data dependent updates of a 64 KiB block */
struct Jit {
	volatile uint8_t *mem;
	uint32_t mask, x;
	uint64_t last;
};

static uint8_t *jitOpen(Jit &j, uint8_t *small256, unsigned extra) {
	uint8_t *block = (uint8_t *) AllocVec(POOL_JIT_MEM + extra, MEMF_ANY);
	j.mem = block ? block : small256;
	j.mask = block ? POOL_JIT_MEM - 1 : 255;
	j.x = (uint32_t) cycles() | 1;
	return block;
}

static uint32_t jitStep(Jit &j, uint32_t prev) {
	uint32_t x = (j.x ^ prev) | 1; /* addresses depend on the last delta */
	for (unsigned k = 0; k < POOL_JIT_STEPS; ++k) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		volatile uint8_t *p = j.mem + (x & j.mask);
		*p = (uint8_t) (*p + k + 1);
	}
	j.x = x;
	uint64_t t = cycles();
	uint32_t d = (uint32_t) (t - j.last);
	j.last = t;
	return d;
}

/* n samples (a multiple of 16) into sha; log keeps the deltas if given */
static void jitter(SHA512 &sha, Jit &j, unsigned n, uint32_t *log) {
	uint32_t d[16], prev = 0;
	j.last = cycles();
	for (unsigned i = 0; i < n; ++i) {
		prev = d[i & 15] = jitStep(j, prev);
		if (log)
			log[i] = prev;
		if ((i & 15) == 15)
			sha.updateDirect(d, sizeof(d));
	}
	wipe(d, sizeof(d));
}

static uint32_t gcd32(uint32_t a, uint32_t b) {
	while (b) {
		uint32_t t = a % b;
		a = b;
		b = t;
	}
	return a;
}

/* Health check, used only for a warning (no entropy credit): at most 1/4 of
   the deltas may be zero, and after dividing by their GCD (a coarse counter
   steps in fixed units) neither the most common low byte nor "same as k
   samples ago" (k = 1..8) may predict 3/4 of them. Constant, short period
   and pure quantisation streams fail, so does a deterministic machine. */
static bool jitterHealthy(const uint32_t *d, unsigned n) {
	uint32_t g = 0;
	unsigned zeros = 0, best = 0;
	for (unsigned i = 0; i < n; ++i)
		if (d[i])
			g = gcd32(d[i], g);
		else
			++zeros;
	if (!g || zeros * 4 >= n)
		return false;
	uint16_t count[256];
	memset(count, 0, sizeof(count));
	for (unsigned i = 0; i < n; ++i) {
		unsigned c = ++count[(d[i] / g) & 255];
		if (c > best)
			best = c;
	}
	for (unsigned k = 1; k <= 8; ++k) {
		unsigned hits = 0;
		for (unsigned i = k; i < n; ++i)
			if (d[i] == d[i - k])
				++hits;
		if (hits > best)
			best = hits;
	}
	return best * 4 < n * 3;
}

/* timer.device wake-ups through exec calls that already run on all targets
   (the daemon's timer, the client's keyboard.device), not DOS Delay(), whose
   x86_64 wrapper is a no-op. Works from a plain Task too. */
static unsigned wakeRounds(SHA512 &sha, Jit &j, unsigned rounds) {
	unsigned done = 0;
	struct MsgPort *port = POOL_CREATE_PORT();
	struct timerequest *tr = port ?
			(struct timerequest *) POOL_CREATE_IO(port, sizeof(struct timerequest)) : 0;
	if (tr && 0 == POOL_OPEN_DEVICE(TIMERNAME, POOL_TIMER_UNIT, &tr->tr_node, 0)) {
		struct Device *TimerBase = tr->tr_node.io_Device; /* used by GetSysTime() */
		union {
			struct timeval tv;
			uint8_t raw[16];
		} now;
		memset(&now, 0, sizeof(now));
		GetSysTime(&now.tv);
		sha.updateDirect(&now, sizeof(now));
		for (unsigned r = 0; r < rounds; ++r) {
			struct {
				uint64_t before, after;
				uint32_t idle, disp;
			} w;
			tr->tr_node.io_Command = TR_ADDREQUEST;
			tr->tr_time.tv_secs = 0;
			tr->tr_time.tv_micro = POOL_WAIT_US + ((uint32_t) cycles() & 1023);
			w.before = cycles();
			if (0 == DoIO(&tr->tr_node))
				++done;
			w.after = cycles();
			w.idle = SysBase->IdleCount;
			w.disp = SysBase->DispCount;
			sha.updateDirect(&w, sizeof(w));
			jitter(sha, j, POOL_JIT_WAKE, 0);
		}
		POOL_CLOSE_DEVICE(&tr->tr_node);
	}
	if (tr)
		POOL_DELETE_IO(tr);
	if (port)
		POOL_DELETE_PORT(port);
	return done;
}

/* fresh samples into sha: a health checked burst, then the wake-ups */
static unsigned collect(SHA512 &sha, unsigned rounds) {
	unsigned flags = 0;
	uint8_t small[256];
	Jit j;
	uint8_t *block = jitOpen(j, small, POOL_JIT_FIRST * 4);
	uint32_t *log = block ? (uint32_t *) (block + POOL_JIT_MEM) : 0;
	jitter(sha, j, POOL_JIT_FIRST, log);
	if (log && jitterHealthy(log, POOL_JIT_FIRST))
		flags |= AROS_RANDPOOL_JITTER_OK;
	if (wakeRounds(sha, j, rounds) == rounds)
		flags |= AROS_RANDPOOL_TIMER_OK;
	if (block) {
		wipe(log, POOL_JIT_FIRST * 4);
		FreeVec(block);
	}
	return flags;
}

/* reads up to 64 bytes, returns the count */
static unsigned readSeed(const char *name, uint8_t *buf) {
	BPTR fh = Open(name, MODE_OLDFILE);
	if (!fh)
		return 0;
	LONG r = Read(fh, buf, 64);
	Close(fh);
	return r > 0 ? (unsigned) r : 0;
}

static void mixSeed(SHA512 &sha, const char *tag, const char *name, uint8_t *buf) {
	unsigned got = readSeed(name, buf);
	sha.updateDirect(tag, 4);
	sha.updateDirect(&got, sizeof(got));
	if (got)
		sha.updateDirect(buf, got);
	wipe(buf, 64);
	if (got == 64)
		poolFlags |= AROS_RANDPOOL_SEED_READ;
}

static __attribute__((noinline)) void seedPool(void) {
	SHA512 sha;
	uint8_t buf[64];
	char seedName[128];
	bool save = false;

	sha.updateDirect(pool, 64);
	sha.updateDirect("init", 4);

	struct Task *me = FindTask(0);
	struct DateStamp ds;
	struct {
		uint64_t cyc, task, stack, sysBase, self, availAny, availLargest;
		int32_t days, minute, tick;
		uint32_t idle, disp;
	} is;
	memset(&ds, 0, sizeof(ds));
	memset(&is, 0, sizeof(is));
	DateStamp(&ds);
	is.cyc = cycles();
	is.task = (uintptr_t) me;
	is.stack = (uintptr_t) &is;
	is.sysBase = (uintptr_t) SysBase;
	is.self = (uintptr_t) pool;
#if !defined(BEBBOSSH_AROS_MINCRT)
	is.availAny = AvailMem(MEMF_ANY);
	is.availLargest = AvailMem(MEMF_ANY | MEMF_LARGEST);
#endif
	is.days = ds.ds_Days;
	is.minute = ds.ds_Minute;
	is.tick = ds.ds_Tick;
	is.idle = SysBase->IdleCount;
	is.disp = SysBase->DispCount;
	sha.updateDirect(&is, sizeof(is));

	/* DOS file calls only from a Process; tc_Node is at offset 0 on x86_64 too */
	const char *dir = sshDotDir;
	unsigned n = dir ? strlen(dir) : 0;
	if (me && me->tc_Node.ln_Type == NT_PROCESS && n
			&& n + sizeof("/random_seed") <= sizeof(seedName)) {
		strcpy(seedName, dir);
		if (dir[n - 1] != ':' && dir[n - 1] != '/')
			strcat(seedName, "/");
		strcat(seedName, "random_seed");
		mixSeed(sha, "file", seedName, buf);
		BPTR l = Lock(dir, SHARED_LOCK);
		if (!l)
			l = CreateDir(dir);
		if (l)
			UnLock(l);
		save = true;
	}

	/* always the full collection: a seed shared by cloned images or VM
	   snapshots must not shorten it */
	poolFlags |= collect(sha, POOL_ROUNDS);
	sha.digestDirect(pool);

	/* The next run starts from a new seed, written before any output. It is
	   overwritten in place (MODE_READWRITE, MODE_NEWFILE only if it is
	   missing): unlike 0008's .tmp + DeleteFile() + Rename(), no crash or
	   concurrent run can lose it. Fails quietly on read-only media. */
	if (save) {
		poolHash(sha, buf, pool, "save", 0, 0);
		BPTR fh = Open(seedName, MODE_READWRITE);
		if (!fh) {
			/* the FFS/OFS handler does not create a missing file with
			   MODE_READWRITE (SFS, FAT and PFS do) */
			BPTR l = Lock(seedName, SHARED_LOCK);
			if (l)
				UnLock(l);
			else
				fh = Open(seedName, MODE_NEWFILE);
		}
		if (fh) {
			if (Write(fh, buf, 64) == 64)
				poolFlags |= AROS_RANDPOOL_SEED_SAVED;
			Close(fh);
		}
		wipe(buf, sizeof(buf));
	}
	wipe(&sha, sizeof(sha));
	wipe(&is, sizeof(is));
	seeded = 1;
}

#if !defined(BEBBOSSH_AROS_MINCRT)
static void poolLock(void) {
	Forbid(); /* lazy init as in 0008, tested inside Forbid() */
	if (!semReady) {
		InitSemaphore(&poolSem);
		semReady = 1;
	}
	Permit();
	ObtainSemaphore(&poolSem);
}

static void poolUnlock(void) {
	ReleaseSemaphore(&poolSem);
}
#else
/* the semaphore wrappers are no-ops and every caller is the main task */
static inline void poolLock(void) {
}

static inline void poolUnlock(void) {
}
#endif

extern "C" void aros_randfill(void *to, unsigned len) {
	poolLock();
	if (!seeded)
		seedPool();

	SHA512 sha;
	struct { /* 32 bytes: pool + tag + sample fit one SHA-512 block */
		uint64_t cyc, buf, stack;
		uint32_t idle, disp;
	} s;
	s.cyc = cycles();
	s.buf = (uintptr_t) to;
	s.stack = (uintptr_t) &s;
	s.idle = SysBase->IdleCount;
	s.disp = SysBase->DispCount;
	poolHash(sha, pool, pool, "stir", &s, sizeof(s));

	uint8_t block[64], ctr[8];
	uint8_t *p = (uint8_t *) to;
	while (len) {
		be64(ctr, ++outCount);
		poolHash(sha, block, pool, "outp", ctr, 8);
		unsigned n = len < 64 ? len : 64;
		memcpy(p, block, n);
		p += n;
		len -= n;
	}
	be64(ctr, outCount);
	poolHash(sha, pool, pool, "next", ctr, 8);

	wipe(block, sizeof(block));
	wipe(&s, sizeof(s));
	wipe(&sha, sizeof(sha));
	poolUnlock();
}

extern "C" void aros_randpool_stir(unsigned rounds) {
	poolLock();
	if (!seeded)
		seedPool();
	SHA512 sha;
	sha.updateDirect(pool, 64);
	sha.updateDirect("more", 4);
	/* the jitter and timer flags report this collection */
	poolFlags = (poolFlags & (AROS_RANDPOOL_SEED_READ | AROS_RANDPOOL_SEED_SAVED))
			| collect(sha, rounds);
	sha.digestDirect(pool);
	wipe(&sha, sizeof(sha));
	poolUnlock();
}

extern "C" unsigned aros_randpool_flags(void) {
	return poolFlags;
}

extern "C" unsigned aros_randpool_sample(uint32_t *deltas, unsigned n) {
	SHA512 sha;
	uint8_t small[256];
	Jit j;
	uint8_t *block = jitOpen(j, small, 0);
	n &= ~15u;
	jitter(sha, j, n, deltas);
	wipe(&sha, sizeof(sha));
	if (!block)
		return 0;
	FreeVec(block);
	return jitterHealthy(deltas, n);
}

#endif
