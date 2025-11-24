/*
 * AmigaSSH - SFTP protocol constants and attribute definitions
 *
 * Copyright (C) 2024-2025  Stefan Franke <stefan@franke.ms>
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
 * Project: AmigaSSH - SSH2 client/server suite for Amiga
 * Purpose: Define constants, message codes, error codes, and attribute flags
 *          for the SFTP (SSH File Transfer Protocol) implementation
 *
 * Features:
 *  - SSH_FXP message type definitions (INIT, VERSION, OPEN, CLOSE, READ, WRITE, etc.)
 *  - SSH_FX status/error codes for protocol compliance
 *  - File attribute flags for size, permissions, timestamps, ownership, and extended metadata
 *  - Utility functions for converting Amiga protection bits to SSH modes and vice versa
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management and compatibility with SSH2/SFTP standards.
 *
 * Author's intent:
 *  Provide a clear, maintainable set of definitions for SFTP protocol handling
 *  to support secure file transfer operations on Amiga systems.
 * ----------------------------------------------------------------------
 */
#ifndef __SFTP_H__
#define __SFTP_H__

#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_SYMLINK			   20
#define SSH_FXP_LINK               21
#define SSH_FXP_BLOCK              22
#define SSH_FXP_UNBLOCK            23

// 0x65
#define SSH_FXP_STATUS            101
#define SSH_FXP_HANDLE            102
#define SSH_FXP_DATA              103
// 0x68
#define SSH_FXP_NAME              104
// 0x69
#define SSH_FXP_ATTRS             105

// 0xC8
#define SSH_FXP_EXTENDED          200
// 0xC9
#define SSH_FXP_EXTENDED_REPLY    201

#define SSH_FX_OK                            0
#define SSH_FX_EOF                           1
#define SSH_FX_NO_SUCH_FILE                  2
#define SSH_FX_PERMISSION_DENIED             3
#define SSH_FX_FAILURE                       4
#define SSH_FX_BAD_MESSAGE                   5
#define SSH_FX_NO_CONNECTION                 6
#define SSH_FX_CONNECTION_LOST               7
#define SSH_FX_OP_UNSUPPORTED                8
#define SSH_FX_INVALID_HANDLE                9
#define SSH_FX_NO_SUCH_PATH                  10
#define SSH_FX_FILE_ALREADY_EXISTS           11
#define SSH_FX_WRITE_PROTECT                 12
#define SSH_FX_NO_MEDIA                      13
#define SSH_FX_NO_SPACE_ON_FILESYSTEM        14
#define SSH_FX_QUOTA_EXCEEDED                15
#define SSH_FX_UNKNOWN_PRINCIPAL             16
#define SSH_FX_LOCK_CONFLICT                 17
#define SSH_FX_DIR_NOT_EMPTY                 18
#define SSH_FX_NOT_A_DIRECTORY               19
#define SSH_FX_INVALID_FILENAME              20
#define SSH_FX_LINK_LOOP                     21
#define SSH_FX_CANNOT_DELETE                 22
#define SSH_FX_INVALID_PARAMETER             23
#define SSH_FX_FILE_IS_A_DIRECTORY           24
#define SSH_FX_BYTE_RANGE_LOCK_CONFLICT      25
#define SSH_FX_BYTE_RANGE_LOCK_REFUSED       26
#define SSH_FX_DELETE_PENDING                27
#define SSH_FX_FILE_CORRUPT                  28
#define SSH_FX_OWNER_INVALID                 29
#define SSH_FX_GROUP_INVALID                 30
#define SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK   31

#define SSH_FILEXFER_ATTR_SIZE              0x00000001
#define SSH2_FILEXFER_ATTR_UIDGID	        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS       0x00000004
#define SSH_FILEXFER_ATTR_ACCESSTIME        0x00000008
#define SSH2_FILEXFER_ATTR_ACMODTIME	0x00000008
#define SSH_FILEXFER_ATTR_CREATETIME        0x00000010
#define SSH_FILEXFER_ATTR_MODIFYTIME        0x00000020
#define SSH_FILEXFER_ATTR_ACL               0x00000040
#define SSH_FILEXFER_ATTR_OWNERGROUP        0x00000080
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES   0x00000100
#define SSH_FILEXFER_ATTR_BITS              0x00000200
#define SSH_FILEXFER_ATTR_ALLOCATION_SIZE   0x00000400
#define SSH_FILEXFER_ATTR_TEXT_HINT         0x00000800
#define SSH_FILEXFER_ATTR_MIME_TYPE         0x00001000
#define SSH_FILEXFER_ATTR_LINK_COUNT        0x00002000
#define SSH_FILEXFER_ATTR_UNTRANSLATED_NAME 0x00004000
#define SSH_FILEXFER_ATTR_CTIME             0x00008000
#define SSH_FILEXFER_ATTR_EXTENDED          0x80000000

#define SSH2_FXF_READ			0x00000001
#define SSH2_FXF_WRITE			0x00000002
#define SSH2_FXF_APPEND			0x00000004
#define SSH2_FXF_CREAT			0x00000008
#define SSH2_FXF_TRUNC			0x00000010
#define SSH2_FXF_EXCL			0x00000020

// rwxd 3-0
static
inline int a2sshmode(ulong m) {
	int a = ((m & 8) ? 0 : 0444) | ((m & 4) ? 0 : 0222) | ((m & 2) ? 0 : 0111);
	return a;
}

static
inline int ssh2amode(ulong m) {
	m |= (m >> 3) | (m >> 6);
	int a = ((m & 4) ? 0 : 8) | ((m & 2) ? 0 : 4) | ((m & 1) ? 0 : 2);
	return a;
}

#endif // __SFTP_H__
