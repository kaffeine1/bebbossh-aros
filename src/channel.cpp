/* -*- coding: iso-8859-1 -*-
 *
 *  bebbossh - Channel abstraction
 *  Copyright (C) 2024-2025  Stefan "Bebbo" Franke <stefan@franke.ms>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License,
 *  or (at your option) any later version (GPLv3+).
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ----------------------------------------------------------------------
 * Project: bebbossh - SSH2/SFTP client/server suite for Amiga
 * Purpose: Define channel base class for SSH session handling
 *
 * Features:
 *  - Channel naming and lifecycle management
 *  - Window size update logic for flow control
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with bsdsocket.library integration.
 *
 * Author's intent:
 *  Provide a clear, maintainable abstraction for SSH channels
 *  with explicit resource management and GPL compliance.
 * ----------------------------------------------------------------------
 */
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr

#ifdef __AMIGA__
#include <proto/socket.h>
#endif

#include <log.h>
#include <sshsession.h>
#include "channel.h"

Channel::~Channel() {
}

char const * Channel::getName() const {
	return server->name;
}

uint32_t Channel::updateWindowSize(uint32_t len) {
	windowSize -= len;
	if (windowSize > 0x10000000)
		return 0;

	windowSize += 0x10000000;
	return 0x10000000;
}
