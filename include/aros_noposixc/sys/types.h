/*
 * <sys/types.h> for the AROS aarch64 build, which is compiled and linked
 * with -noposixc. That option removes the posixc headers from the include
 * path; the types alone come from the header itself.
 */
#ifndef BEBBOSSH_NOPOSIXC_SYS_TYPES_H
#define BEBBOSSH_NOPOSIXC_SYS_TYPES_H

#include <aros/posixc/sys/types.h>

#endif
