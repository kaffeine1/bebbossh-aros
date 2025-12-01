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

static bool init;
static struct MsgPort *kmp;
static struct IOStdReq *kio;
static bool kdev;
static UBYTE *matrix;

static void closeKeyboardSupport() {
	if (matrix)
		free(matrix);
	if (kdev)
		CloseDevice((struct IORequest* )kio);
//	if (kio)
//		DeleteExtIO((struct IORequest*) kio);
	if (kmp)
		DeletePort(kmp);
}

uint32_t getKeyboardQualifiers() {
	if (!init) {
		// init once
		init = true;

		// cleanup at exit
		atexit(closeKeyboardSupport);
	
		kmp = CreatePort(0, 0);
		if (!kmp)
			return 0;
		kio = (struct IOStdReq*) CreateExtIO(kmp, sizeof(struct IOStdReq));
		if (!kio)
			return 0;

		kdev = !OpenDevice("keyboard.device", 0, (struct IORequest* )kio, 0);
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
