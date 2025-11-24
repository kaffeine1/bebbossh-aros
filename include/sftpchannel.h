/*
 * AmigaSSH - SFTP channel implementation
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
 * Purpose: Define the SftpChannel class for handling SFTP requests and responses
 *
 * Features:
 *  - Handle struct to manage file descriptors, metadata, and state
 *  - SftpChannel class to process SFTP packets and manage active handles
 *  - Support for status responses, name responses, and packet transmission
 *  - Integration with SSH session for channel lifecycle management
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management and compatibility with SFTP protocol.
 *
 * Author's intent:
 *  Provide a clear, maintainable implementation of SFTP channels
 *  to support secure file transfer operations within SSH sessions.
 * ----------------------------------------------------------------------
 */
#ifndef SFTPCHANNEL_H_
#define SFTPCHANNEL_H_

#include <sshsession.h>
#include <stack.h>

struct Handle {
	uint8_t handle[12];
	uint32_t idx;
	struct FileInfoBlock fib;
	char * filename;
	BPTR file;
	BPTR dir;
	bool first;
	bool eof;

	Handle(char const * name, BPTR file, BPTR dir, uint32_t id);
	~Handle();
};

class SftpChannel : public Channel {
	uint32_t requestId;
	uint32_t flags;
	uint32_t limit;

	Stack<Handle> handles;

	void * queue;
	int queueLen;

	void newHandle(uint8_t * &q, uint8_t const * path, BPTR file, BPTR dir);
	Handle * findHandle(uint8_t * hdata) const;
	void makeStatus(uint8_t * &q, uint32_t result);
	void sendPacket(uint8_t *q, uint8_t * &out);
	void makeNameResponse(uint8_t * &q, char const * path, struct FileInfoBlock *fib);

	void flush(uint8_t * out);

public:
	SftpChannel(SshSession * server, uint32_t channel);
	virtual ~SftpChannel();

	virtual void abort();
	virtual int handleData(char * buffer, unsigned len);

	virtual bool isBufferFree() const {
		return true;
	}
	virtual int processSocketData(void * data, int len);
	void close();
};


#endif /* SFTPCHANNEL_H_ */
