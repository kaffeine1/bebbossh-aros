/*
 * bebbossh - keyboard support utilities
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
 * Project: bebbossh - SSH2 client/server suite for Amiga
 * Purpose: Provide keyboard qualifier detection and message port helpers
 *
 * Features:
 *  - Query keyboard.device for current key matrix
 *  - Return qualifier flags (Shift, Ctrl, Alt, Amiga keys)
 *  - Utility functions for creating/deleting MsgPorts and IORequests
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management.
 *
 * Author's intent:
 *  Supply maintainable, GPL-compliant keyboard support routines
 *  for integration into bebbossh client/server components.
 * ----------------------------------------------------------------------
 */
#if defined(__AROS__) && !defined(__AMIGA__)
#define __AMIGA__ 1
#endif

#include <platform.h>

#ifdef __AMIGA__
#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <dos/dos.h>
#include <devices/keyboard.h>
#include <clib/alib_protos.h>
#include <proto/dos.h>
#include <proto/exec.h>

#include <stdlib.h>
#include <string.h>

#include "keyboard.h"

#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT) && defined(__x86_64__)
// x86_64/mincrt: the local CreatePort()/DeletePort() below call exec directly,
// so the port and request go through the mincrt-safe exec wrappers instead.
#include <aros_mincrt_wrappers.h>
#define KBD_CREATE_PORT() bebbossh_aros_create_msgport()
#define KBD_DELETE_PORT(p) bebbossh_aros_delete_msgport(p)
#define KBD_CREATE_IO(p, s) bebbossh_aros_create_iorequest((p), (s))
#define KBD_DELETE_IO(r) bebbossh_aros_delete_iorequest(r)
#define KBD_OPEN_DEVICE(n, u, r, f) bebbossh_aros_open_device((n), (u), (r), (f))
#define KBD_CLOSE_DEVICE(r) bebbossh_aros_close_device(r)
#elif defined(__AROS__) && defined(__aarch64__)
// aarch64: clib/alib_protos.h declares CreatePort() and CreateExtIO(), so the
// calls would bind to amiga.lib while the local DeletePort() below frees with
// FreeMem through *(APTR *)4: use the exec calls on both sides.
#define KBD_CREATE_PORT() CreateMsgPort()
#define KBD_DELETE_PORT(p) DeleteMsgPort(p)
#define KBD_CREATE_IO(p, s) CreateIORequest((p), (s))
#define KBD_DELETE_IO(r) DeleteIORequest((struct IORequest *)(r))
#define KBD_OPEN_DEVICE(n, u, r, f) OpenDevice((n), (u), (r), (f))
#define KBD_CLOSE_DEVICE(r) CloseDevice(r)
#else
#define KBD_CREATE_PORT() CreatePort(0, 0)
#define KBD_DELETE_PORT(p) DeletePort(p)
#define KBD_CREATE_IO(p, s) CreateExtIO((p), (s))
#define KBD_DELETE_IO(r) ((void)(r))
#define KBD_OPEN_DEVICE(n, u, r, f) OpenDevice((n), (u), (r), (f))
#define KBD_CLOSE_DEVICE(r) CloseDevice(r)
#endif

static bool init;
static struct MsgPort *kmp;
static struct IOStdReq *kio;
static bool kdev;
static UBYTE *matrix;

static void closeKeyboardSupport() {
	if (matrix)
		free(matrix);
	if (kdev)
		KBD_CLOSE_DEVICE((struct IORequest* )kio);
	if (kio)
		KBD_DELETE_IO(kio);
	if (kmp)
		KBD_DELETE_PORT(kmp);
}

uint32_t getKeyboardQualifiers() {
	if (!init) {
		// init once
		init = true;

		// cleanup at exit
		atexit(closeKeyboardSupport);
	
		kmp = KBD_CREATE_PORT();
		if (!kmp)
			return 0;
		kio = (struct IOStdReq*) KBD_CREATE_IO(kmp, sizeof(struct IOStdReq));
		if (!kio)
			return 0;

		kdev = !KBD_OPEN_DEVICE("keyboard.device", 0, (struct IORequest* )kio, 0);
		if (!kdev)
			return 0;

		matrix = (UBYTE*) malloc(16);
	}
	if (!matrix)
		return 0;

	// query key state
	kio->io_Command = KBD_READMATRIX;
	kio->io_Data = (APTR) matrix;
	kio->io_Length = 16;
	DoIO((struct IORequest* )kio);
	
	return ((matrix[12] & (1<<0)) ? LSHIFT : 0)
		 | ((matrix[12] & (1<<1)) ? RSHIFT : 0)
		 | ((matrix[12] & (1<<2)) ? CAPSLOCK : 0)
		 | ((matrix[12] & (1<<3)) ? CTRL : 0)
		 | ((matrix[12] & (1<<4)) ? ALT : 0)
		 | ((matrix[12] & (1<<6)) ? LAMIGA : 0)
		 | ((matrix[12] & (1<<7)) ? RAMIGA : 0);
}

#define NEWLIST(l) ((l)->lh_Head = (struct Node *)&(l)->lh_Tail, \
                    /*(l)->lh_Tail = NULL,*/ \
                    (l)->lh_TailPred = (struct Node *)&(l)->lh_Head)

__stdargs struct MsgPort *CreatePort(CONST_STRPTR name,LONG pri)
{ APTR SysBase = *(APTR *)4L;
  struct MsgPort *port = NULL;
  UBYTE portsig;

  if ((BYTE)(portsig=AllocSignal(-1)) >= 0) {
    if (!(port= (struct MsgPort *)AllocMem(sizeof(*port),MEMF_CLEAR|MEMF_PUBLIC)))
      FreeSignal(portsig);
    else {
      port->mp_Node.ln_Type = NT_MSGPORT;
      port->mp_Node.ln_Pri  = pri;
      port->mp_Node.ln_Name = (char *)name;
      /* done via AllocMem
      port->mp_Flags        = PA_SIGNAL;
      */
      port->mp_SigBit       = portsig;
      port->mp_SigTask      = FindTask(NULL);
      NEWLIST(&port->mp_MsgList);
      if (port->mp_Node.ln_Name)
        AddPort(port);
    }
  }
  return port;
}

__stdargs VOID DeletePort(struct MsgPort *port)
{ APTR SysBase = *(APTR *)4L;

  if (port->mp_Node.ln_Name)
    RemPort(port);
  FreeSignal(port->mp_SigBit); FreeMem(port,sizeof(*port));
}

__stdargs struct IORequest* CreateExtIO(CONST struct MsgPort *port, LONG iosize) {
	struct IORequest *ioreq = NULL;
	if (port && (ioreq = (struct IORequest*) malloc(iosize))) {
		memset(ioreq, 0, iosize);
		ioreq->io_Message.mn_Node.ln_Type = NT_REPLYMSG;
		ioreq->io_Message.mn_ReplyPort = (struct MsgPort*) port;
		ioreq->io_Message.mn_Length = iosize;
	}
	return ioreq;
}
#endif
