/*
 * <errno.h> for the AROS aarch64 build without posixc.library: the stdc
 * header plus EAGAIN, which bsdsocket.library reports through Errno().
 */
#ifndef BEBBOSSH_NOPOSIXC_ERRNO_H
#define BEBBOSSH_NOPOSIXC_ERRNO_H

#include_next <errno.h>

#ifndef EAGAIN
#define EAGAIN 35
#endif

#endif
