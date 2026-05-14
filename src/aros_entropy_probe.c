#include <stdint.h>
#include <sys/time.h>
#include <dos/dos.h>
#include <exec/memory.h>
#include <proto/dos.h>
#include <proto/exec.h>

static uint64_t probe_rdtsc(void)
{
#if (defined(__i386__) || defined(__x86_64__)) && defined(__GNUC__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

static void print_u64(const char *name, uint64_t value)
{
    Printf("%s=%08lx%08lx\n", name,
            (unsigned long)(value >> 32),
            (unsigned long)(value & 0xffffffffUL));
}

int main(void)
{
    struct timeval tv;
    struct DateStamp ds;
    APTR task = FindTask(0);
    ULONG largest = AvailMem(MEMF_LARGEST);
    ULONG any = AvailMem(MEMF_ANY);
    uint64_t t0 = probe_rdtsc();
    uint64_t t1 = probe_rdtsc();

    Printf("aros entropy probe: main reached\n");
    Printf("task=%08lx stack=%08lx\n", (unsigned long)(IPTR)task, (unsigned long)(IPTR)&task);
    Printf("mem_largest=%lu mem_any=%lu\n", (unsigned long)largest, (unsigned long)any);
    print_u64("rdtsc0", t0);
    print_u64("rdtsc1", t1);
    print_u64("rdtsc_delta", t1 - t0);

    if (gettimeofday(&tv, 0) == 0) {
        Printf("gettimeofday=%ld.%06ld\n", (long)tv.tv_sec, (long)tv.tv_usec);
    } else {
        Printf("gettimeofday=failed\n");
    }

    DateStamp(&ds);
    Printf("datestamp_days=%ld minute=%ld tick=%ld\n",
            (long)ds.ds_Days, (long)ds.ds_Minute, (long)ds.ds_Tick);

    return 0;
}
