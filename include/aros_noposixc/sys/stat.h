/*
 * <sys/stat.h> for the AROS aarch64 build without posixc.library. The AROS
 * code paths use dos.library for files and directories; mkdir() is in
 * src/aros_noposixc.c.
 */
#ifndef BEBBOSSH_NOPOSIXC_SYS_STAT_H
#define BEBBOSSH_NOPOSIXC_SYS_STAT_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int mkdir(const char *path, mode_t mode);

#ifdef __cplusplus
}
#endif

#endif
