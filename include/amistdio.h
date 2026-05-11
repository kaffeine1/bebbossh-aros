#ifndef BEBBOSSH_COMPAT_AMISTDIO_H
#define BEBBOSSH_COMPAT_AMISTDIO_H

#if defined(__AROS__)
#include <stdio.h>
#else
#include_next <amistdio.h>
#endif

#endif
