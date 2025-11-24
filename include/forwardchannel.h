/*
 * AmigaSSH - SSH port forwarding channel implementation
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
 * Purpose: Implement port forwarding channels and listeners for SSH connections
 *
 * Features:
 *  - ForwardListener struct to manage incoming forwarded connections
 *  - ForwardChannel class to handle socket addresses and forwarding logic
 *  - Integration with SSH session for channel lifecycle management
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management and socket integration.
 *
 * Author's intent:
 *  Provide a clear, maintainable implementation of SSH port forwarding
 *  to support secure tunneling and connection redirection.
 * ----------------------------------------------------------------------
 */
#ifndef __FORWARDLISTENERCHANNEL_H_
#define __FORWARDLISTENERCHANNEL_H_

#include <channel.h>
#include <sshsession.h>

// Forward declarations
class ForwardChannel;

/**
 * Listener for forwarded port connections
 */
struct ForwardListener : public Listener {
    ForwardChannel *fwc;  // Parent forwarding channel

    /**
     * Construct a new ForwardListener
     * @param fwc_ Parent ForwardChannel instance
     */
    ForwardListener(ForwardChannel *fwc_);
    ~ForwardListener();

    /**
     * Check if buffer is available for writing
     * @return true if buffer is free
     */
    virtual bool isBufferFree() const;

    /**
     * Process data received from socket
     * @param data Received data buffer
     * @param len Length of received data
     * @return Number of bytes processed
     */
    virtual int processSocketData(void *data, int len);

    /**
     * Close the listener
     */
    virtual void close();
};

/**
 * SSH port forwarding channel implementation
 */
class ForwardChannel : public Channel {
    struct sockaddr_in sinLocal;   // Local socket address
    struct sockaddr_in sinRemote;  // Remote socket address

    ForwardListener listener;      // Associated listener instance

public:
    /**
     * Construct a new ForwardChannel
     * @param server SSH session instance
     * @param channel Channel identifier
     */
    ForwardChannel(SshSession *server, uint32_t channel);
    virtual ~ForwardChannel();

    /**
     * Get socket file descriptor
     * @return Socket file descriptor
     */
    int getSockFd() const;

    /**
     * Initialize forwarding channel
     * @param from Source address (IP)
     * @param fromPort Source port
     * @param to Destination address (IP)
     * @param toPort Destination port
     * @return true on success, false on failure
     */
    bool init(uint8_t *from, uint32_t fromPort, uint8_t *to, uint32_t toPort);

    // Channel interface implementation
    virtual void abort();
    virtual int handleData(char *buffer, unsigned len);

    /**
     * Check if buffer is available for writing
     * @return Always returns true (buffering handled elsewhere)
     */
    virtual bool isBufferFree() const { return true; }

    /**
     * Get associated listener instance
     * @return Pointer to listener
     */
    inline Listener *getListener() { return &listener; }

    /**
     * Process data received from socket
     * @param data Received data buffer
     * @param len Length of received data
     * @return Number of bytes processed
     */
    int processSocketData(void *data, int len);

    /**
     * Request channel closure
     */
    inline void closeChannel() { server->closeChannel(this); }
};

#endif /* __FORWARDLISTENERCHANNEL_H_ */
