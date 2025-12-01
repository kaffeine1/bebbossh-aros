/*
 * bebbossh - client channel handling
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
 * Project: bebbossh - SSH2 client for the Amiga
 * Purpose: Manage SSH channel lifecycle, flow control, and message dispatch
 *
 * Features:
 *  - Channel open/confirm/close and EOF handling
 *  - Window size accounting with SSH_MSG_CHANNEL_WINDOW_ADJUST
 *  - Data framing and per-channel processing hooks
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Explicit buffer usage; avoid hidden side effects.
 *
 * Author's intent:
 *  Provide a clear, maintainable channel abstraction with robust
 *  flow control and predictable behavior on classic Amiga systems.
 * ----------------------------------------------------------------------
 */
#include "ssh.h"
#include "log.h"
#include "clientchannel.h"

extern uint32_t maxBuffer;
extern uint8_t *buffer;

extern void checkChannelFinished(ClientChannel * cc);

ClientChannel::ClientChannel(uint32_t no) :
		channelNo(no), remoteChannelNo(-1), windowSize(0x20000000), maxBuffer(::maxBuffer), state(0) {
}

ClientChannel::~ClientChannel() {

}

void ClientChannel::confirm(uint32_t no, uint32_t mb) {
	state |= CONFIRMED;
	remoteChannelNo = no;
	maxBuffer = mb;
}

Listener* ClientChannel::getListener() {
	return 0;
}

uint32_t ClientChannel::updateWindowSize(uint32_t length) {
	windowSize -= length;
	if (windowSize > 0x10000000)
		return 0;

	windowSize += 0x10000000;
	return 0x10000000;
}

void ClientChannel::closeChannel(uint16_t flag) {
	// channelNo == 0 does not use open/eof/close
	if (channelNo) {
		uint8_t * p;
		if ((flag & ClientChannel::CLIENT_EOF) && !(getState() & ClientChannel::CLIENT_EOF)) {
			logme(L_DEBUG, "send eof for channel %ld/%ld", channelNo, getRemoteChannelNo());
			// send eof if not sent
			p = buffer + 5;
			*p++ = SSH_MSG_CHANNEL_EOF;
			putInt32AndInc(p, getRemoteChannelNo());
			sendEncrypted(buffer + 5, 5);
		}
		if ((flag & ClientChannel::CLIENT_CLOSE) && !(getState() & ClientChannel::CLIENT_CLOSE)) {
			logme(L_DEBUG, "send close for channel %ld/%ld", channelNo, getRemoteChannelNo());
			// send close if not sent
			p = buffer + 5;
			*p++ = SSH_MSG_CHANNEL_CLOSE;
			putInt32AndInc(p, getRemoteChannelNo());
			sendEncrypted(buffer + 5, 5);
		}
	}
	addState(flag);
	checkChannelFinished(this);
	return;
}

bool ClientChannel::handleMessage(uint8_t msg, uint8_t * p, uint32_t maxLen) {
	if (msg == SSH_MSG_CHANNEL_DATA) {
		uint32_t length = getInt32(p);
		p += 4;
		p[length] = 0;

		logme(L_FINE, "channel %ld got %ld bytes in %ld", channelNo, length, maxLen);
		if (processChannelData(p, length) < 0) {
			logme(L_DEBUG, "stopped since channel %ld/%ld ended", channelNo, getRemoteChannelNo());
			return false;
		}

		uint32_t toAdd = updateWindowSize(length);
		if (toAdd) {

			static uint8_t CHANNEL_WINDOW_ADJUST[16] = { 0, 0, 0, 12, 2,
					SSH_MSG_CHANNEL_WINDOW_ADJUST,
					0, 0, 0, 0,
					0, 0, 0, 0,
					0, 1 };

			uint8_t * p = &CHANNEL_WINDOW_ADJUST[6];
			putInt32AndInc(p, getRemoteChannelNo());
			putInt32AndInc(p, toAdd);

			sendEncrypted(CHANNEL_WINDOW_ADJUST, sizeof(CHANNEL_WINDOW_ADJUST));
		}
		return true;
	}

	if (msg == SSH_MSG_CHANNEL_REQUEST) {

		// it's a logout
		if (*(uint32_t *)(p) == 11 && 0 == strncmp((char *)p + 4, "exit-status", 11)) {
			if (channelNo == 0) {
				logme(L_DEBUG, "exit since channel %ld ended", channelNo);
				return false;
			}
		}

		// TODO: handle more channel requests: reverse forwarding

		return true;
	}

	if (msg == SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
		uint32_t remoteChannelNo = getInt32(p);
		p += 4;
		// uint32_t windowSize = getInt32(p); // ignore :-)
		p += 4;
		uint32_t maxBuf = getInt32(p);

		logme(L_DEBUG, "channel %ld confirmend, remote=%ld", channelNo, remoteChannelNo);

		confirm(remoteChannelNo, maxBuf);
		return true;
	}

	if (msg == SSH_MSG_CHANNEL_EOF) {
		logme(L_DEBUG, "eof for channel %ld", channelNo);

		closeChannel(ClientChannel::SERVER_EOF | ClientChannel::CLIENT_EOF);
		return true;
	}

	if (msg == SSH_MSG_CHANNEL_CLOSE) {
		logme(L_DEBUG, "close for channel %ld", channelNo);
		closeChannel(ClientChannel::SERVER_CLOSE | ClientChannel::CLIENT_CLOSE);
		return true;
	}

	if (msg == SSH_MSG_CHANNEL_OPEN_FAILURE) {
		uint32_t err = getInt32(p);
		p += 4;
		uint8_t * s = sshString(p);
		logme(L_ERROR, "channel %ld open error %ld: %s", channelNo, err, s);

		closeChannel(0);
		return true;
	}

	if (msg == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
		return true;
	}

	return false;
}
