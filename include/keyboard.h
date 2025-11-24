/*
 * AmigaSSH - Keyboard qualifier bit definitions
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
 * Purpose: Define bitmask constants for keyboard qualifiers (modifier keys)
 *
 * Features:
 *  - Bitmask definitions for Shift, Caps Lock, Control, Alt, and Amiga keys
 *  - Function prototype to query current keyboard qualifier state
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management.
 *
 * Author's intent:
 *  Provide clear, maintainable definitions for keyboard qualifier handling
 *  to support SSH client/server input processing on Amiga systems.
 * ----------------------------------------------------------------------
 */
#ifndef __KEYBOARD_H__
#define __KEYBOARD_H__

#include <inttypes.h>

/**
 * Keyboard qualifier bitmask definitions
 * These bits represent the state of modifier keys
 */
#define LSHIFT    0x01  // Left Shift key pressed
#define RSHIFT    0x02  // Right Shift key pressed
#define CAPSLOCK  0x04  // Caps Lock active
#define CTRL      0x08  // Control key pressed
#define ALT       0x10  // Alt key pressed
#define LAMIGA    0x20  // Left Amiga key pressed
#define RAMIGA    0x40  // Right Amiga key pressed

/**
 * Get current keyboard qualifier state
 * @return Bitmask of active qualifiers (see LSHIFT, RSHIFT, etc.)
 */
extern uint32_t getKeyboardQualifiers();

#endif // __KEYBOARD_H__
