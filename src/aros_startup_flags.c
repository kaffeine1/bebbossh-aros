#ifndef AROS_NOSTDIOWIN
#define AROS_NOSTDIOWIN 1
#endif

int __nostdiowin = AROS_NOSTDIOWIN;
int __nowbsupport = 1;

#if defined(BEBBOSSH_AROS_MINCRT) && !defined(AROS_ENABLE_INITEXITSETS)
int __noinitexitsets = 1;
#endif

#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT)
#include <exec/execbase.h>
#include <aros/symbolsets.h>

struct ExecBase *SysBase;
void ___startup_entries_next(struct ExecBase *SysBase);

static void bebbossh_aros_set_sysbase(struct ExecBase *sysBase)
{
	SysBase = sysBase;
	___startup_entries_next(sysBase);
}

ADD2SET(bebbossh_aros_set_sysbase, PROGRAM_ENTRIES, -126)

THIS_PROGRAM_HANDLES_SYMBOLSET(LIBS)
THIS_PROGRAM_HANDLES_SYMBOLSET(INIT)
#endif
