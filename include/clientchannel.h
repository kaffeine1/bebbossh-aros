/*
 * AmigaSSH - SSH client channel implementation
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
 * Purpose: Define client-side channel classes for managing communication
 *          with the SSH server
 *
 * Features:
 *  - Base ClientChannel class with state flags and flow control
 *  - Support for message handling, closing, and window size updates
 *  - Specialized ClientListenerChannel for port forwarding
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management and socket integration.
 *
 * Author's intent:
 *  Provide a clear, maintainable abstraction for SSH client channels
 *  to support interactive sessions, forwarding, and protocol compliance.
 * ----------------------------------------------------------------------
 */
#ifndef __CLIENT_CHANNEL_H__
#define __CLIENT_CHANNEL_H__

#include <inttypes.h>
#include <stack.h>

/**
 * Base class for SSH client channels.
 * Manages channel state and communication with the server.
 */
class ClientChannel {
protected:
    uint32_t channelNo;        // Local channel identifier
    uint32_t remoteChannelNo;  // Remote channel identifier
    uint32_t windowSize;      // Current window size (flow control)
    uint32_t maxBuffer;       // Maximum buffer size allowed
    uint16_t state;           // Channel state flags

public:
    // Channel state flags
    static const uint16_t UNCONFIRMED  = 0;      // Channel not yet confirmed
    static const uint16_t CONFIRMED    = 1 << 0; // Channel confirmed by server
    static const uint16_t CLIENT_EOF   = 1 << 1; // Client sent EOF
    static const uint16_t CLIENT_CLOSE = 1 << 2; // Client closed channel
    static const uint16_t SERVER_EOF   = 1 << 3; // Server sent EOF
    static const uint16_t SERVER_CLOSE = 1 << 4; // Server closed channel
    static const uint16_t FINISHED     = CLIENT_CLOSE | SERVER_CLOSE; // Channel fully closed

    /**
     * Construct a new client channel.
     * @param no Local channel number
     */
    ClientChannel(uint32_t no);
    virtual ~ClientChannel();

    /**
     * Get local channel number.
     * @return Channel identifier
     */
    uint32_t getChannelNo() const { return channelNo; }

    /**
     * Get remote channel number.
     * @return Remote channel identifier
     */
    uint32_t getRemoteChannelNo() const { return remoteChannelNo; }

    /**
     * Handle incoming channel message.
     * @param msg Message type
     * @param p Message data
     * @param maxLen Maximum message length
     * @return true if message was handled successfully
     */
    bool handleMessage(uint8_t msg, uint8_t *p, uint32_t maxLen);

    /**
     * Close the channel with specified flags.
     * @param flag Close flags (CLIENT_CLOSE or SERVER_CLOSE)
     */
    void closeChannel(uint16_t flag);

    /**
     * Update channel window size.
     * @param length Bytes to add to window
     * @return New window size
     */
    uint32_t updateWindowSize(uint32_t length);

    // Pure virtual interface methods
    virtual bool start() = 0;
    virtual int processChannelData(void *data, int len) = 0;
    virtual void confirm(uint32_t no, uint32_t mb);
    virtual Listener *getListener();

    /**
     * Check if channel is confirmed by server.
     * @return true if channel is confirmed
     */
    inline bool isConfirmed() const { return state & CONFIRMED; }

    /**
     * Check if channel can be removed.
     * @return true if channel is finished or unconfirmed
     */
    inline bool canBeRemoved() const {
        return (state & FINISHED) == FINISHED  // Fully closed
            || !(state & CONFIRMED);          // Never confirmed
    }

    /**
     * Check if channel can read data.
     * @return true if no EOF received
     */
    inline bool canRead() const {
        return (state & CLIENT_EOF) == 0; // No EOF seen
    }

    /**
     * Add state flags to channel.
     * @param flag Flags to add
     * @return New state
     */
    inline uint16_t addState(uint16_t flag) { return state |= flag; }

    /**
     * Get current channel state.
     * @return State flags
     */
    inline uint16_t getState() const { return state; }
};

/**
 * Specialized channel for port forwarding listeners.
 */
class ClientListenerChannel : public ClientChannel {
public:
    /**
     * Construct a new listener channel.
     * @param no Local channel number
     */
    ClientListenerChannel(uint32_t no) : ClientChannel(no) {}
};

#endif // __CLIENT_CHANNEL_H__
