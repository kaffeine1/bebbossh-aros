/*
 * AmigaSSH - SSH client core definitions and global state
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
 * Purpose: Define core structures, error codes, and global state for the SSH client
 *
 * Features:
 *  - Enumeration of client error codes for connection, authentication, and protocol handling
 *  - Global state variables for buffers, channels, and connection parameters
 *  - Function prototypes for encrypted communication, event loop, and keyboard handling
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management and BSD socket integration.
 *
 * Author's intent:
 *  Provide a clear, maintainable foundation for SSH client functionality
 *  with robust error handling and global state management.
 * ----------------------------------------------------------------------
 */

#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <stack.h>

// Forward declarations
struct Acceptor;
struct ClientChannel;
struct Listener;
struct Window;

/**
 * SSH client error codes
 */
enum err {
    NO_ERROR = 0,               // No error occurred
    ERROR_NOMEM = 10,           // Memory allocation failure
    ERROR_BSDSOCKET,            // BSD socket initialization error
    ERROR_SOCKET,               // Socket operation error
    ERROR_RESOLVE,              // Hostname resolution failure
    ERROR_CONNECT,              // Connection establishment failure
    ERROR_WRITE,                // Socket write error
    ERROR_READ,                 // Socket read error
    ERROR_WRONG_PACKET,         // Unexpected packet received
    ERROR_INVALID_PACKET,       // Malformed packet received
    ERROR_SIGNATURE_MISMATCH,   // Cryptographic signature mismatch
    ERROR_SERVER_PUBKEY,        // Server public key error
    ERROR_HOST_VERIFY,          // Host verification failure
    ERROR_NO_AUTH_SERVICE,      // Authentication service unavailable
    ERROR_NO_PASSWORD_METHOD,   // Password authentication not supported
    ERROR_NO_LOGIN,             // Login attempt failed
    ERROR_BIND,                 // Port binding failure
    ERROR_NO_HOST,              // No host specified
    ERROR_NO_USER,              // No username specified
    ERROR_NOCIPHERS,            // No compatible ciphers available
    ERROR_LAST                  // Sentinel value
};

// Global client state variables
extern err error;               // Current error state
extern short stopped;           // Client run status flag
extern uint8_t *buffer;         // Data buffer pointer
extern unsigned buffersize;      // Current buffer size

extern uint32_t maxBuffer;      // Maximum remote buffer size (flow control)

extern short escape;            // Escape sequence detection flag
extern struct Window *theWindow; // UI window handle

extern BPTR stdinBptr;          // Standard input file handle
extern BPTR stdoutBptr;         // Standard output file handle

// Connection parameters
extern int port;                // SSH server port
extern char const *hostname;    // SSH server hostname
extern char const *username;    // Authentication username
extern char const *keyFile;     // Private key file path

// Channel and connection management
extern Stack<ClientChannel> clientChannels;  // Active client channels
extern Stack<Acceptor> initacceptors;        // Initial acceptors
extern Stack<Listener> listeners;            // Port listeners

/**
 * Send encrypted data to the server.
 * @param data Pointer to data to send
 * @param len Length of data in bytes
 * @return true on success, false on failure
 */
extern bool sendEncrypted(uint8_t const *data, int len);

/**
 * Receive and process an encrypted packet from the server.
 * @return 0 on success, non-zero on error
 */
extern int receiveEncryptedPacket();

/**
 * Main client event loop.
 */
extern void runClient();

/**
 * Handle keyboard input events.
 */
extern void handleKeyboard();

#endif // __CLIENT_H__
