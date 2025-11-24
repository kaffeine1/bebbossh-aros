/*
 * AmigaSSH - SSH channel abstraction layer
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
 * Purpose: Provide a base abstraction for SSH channels
 *
 * Features:
 *  - Enumeration of channel types (session, exec, forward)
 *  - Common interface for abort, data handling, break signals, and timeouts
 *  - Window size management and channel identification
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management.
 *
 * Author's intent:
 *  Deliver a clear, maintainable abstraction layer for SSH channels
 *  to support interactive shells, command execution, and port forwarding.
 * ----------------------------------------------------------------------
 */
#ifndef CHANNEL_H_
#define CHANNEL_H_

/**
 * Enumeration of SSH channel types.
 */
enum ChannelType {
    UNKNOWN,    // Undefined channel type
    C_SESSION,  // Interactive shell session
    C_EXEC,     // Command execution channel
    C_FORWARD   // Port forwarding channel
};

struct SshSession; // Forward declaration

/**
 * Base class for SSH channel implementations.
 * Provides common functionality for all channel types.
 */
class Channel {
protected:
    struct SshSession *server;  // Pointer to SSH session context
    uint32_t channel;          // Channel identifier
    uint32_t windowSize;       // Current window size in bytes
    ChannelType type;          // Channel type

public:
    /**
     * Construct a new Channel instance.
     * @param server_ Pointer to SSH session context
     * @param channel_ Channel identifier
     * @param type_ Channel type
     */
    Channel(SshSession *server_, uint32_t channel_, ChannelType type_)
        : server(server_), 
          channel(channel_), 
          windowSize(0x20000000), // Initial window size (512MB)
          type(type_) 
    {}

    virtual ~Channel();

    /**
     * Abruptly terminate the channel.
     */
    virtual void abort() = 0;

    /**
     * Handle incoming data for this channel.
     * @param buffer Pointer to received data
     * @param len Length of received data in bytes
     * @return 0 on success, non-zero on error
     */
    virtual int handleData(char *buffer, unsigned len) = 0;

    /**
     * Send break signal to the channel (default no-op).
     */
    virtual void sendBreak() {}

    /**
     * Check for channel timeout (default no-op).
     * @param tv Pointer to timeval structure
     */
    virtual void checkTimeout(struct timeval *tv) {};

    /**
     * Get the associated SSH server session.
     * @return Pointer to SshSession instance
     */
    inline SshSession *getServer() const { return server; }

    /**
     * Get the channel identifier.
     * @return Channel ID
     */
    inline uint32_t getChannel() const { return channel; }

    /**
     * Check if this is a session channel.
     * @return true if channel type is C_SESSION
     */
    inline bool isSession() const { return type == C_SESSION; }

    /**
     * Check if this is a forwarding channel.
     * @return true if channel type is C_FORWARD
     */
    inline bool isForward() const { return type == C_FORWARD; }

    /**
     * Get human-readable name of channel type.
     * @return Channel type name string
     */
    char const *getName() const;

    /**
     * Update the channel window size.
     * @param increment Bytes to add to window size
     * @return New window size
     */
    uint32_t updateWindowSize(uint32_t increment);
};

#endif /* CHANNEL_H_ */
