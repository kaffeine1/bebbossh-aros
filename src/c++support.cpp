/*
 * bebbossh C++ runtime shim (Amiga / cross-platform)
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
 * Project: bebbossh
 * Purpose: Provide minimal operator new/delete and runtime stubs for
 *          Amiga builds and cross-platform compatibility.
 *
 * Features:
 *  - Custom operator new/delete mapped to malloc/free
 *  - Runtime stubs for __cxa_pure_virtual and guard functions
 *  - Weak frame registration stub for exception handling
 *
 * Notes:
 *  - This file ensures C++ linkage works on Amiga without full libstdc++
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include <stdlib.h>
#include <string.h>

#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif

// Provide global symbols for operator new/delete variants
asm("__Znaj: .globl __Znaj");
asm("__Znam: .globl __Znam");

/// Operator new mapped to malloc
void* operator new(size_t sz) {
    return malloc(sz);
}

asm("__ZdaPv: .globl __ZdaPv");
asm("__ZdlPvj: .globl __ZdlPvj");
asm("__ZdaPvj: .globl __ZdaPvj");
asm("__ZdlPvm: .globl __ZdlPvm");
asm("__ZdaPvm: .globl __ZdaPvm");

/// Operator delete mapped to free
void operator delete(void* p) {
    free(p);
}

#ifndef __AMIGA__

/// Array new/delete for non-Amiga builds
void* operator new[](unsigned long s) {
    return malloc(s);
}
void operator delete(void* p, unsigned long) {
    free(p);
}
void operator delete[](void* p) {
    free(p);
}
void operator delete[](void* p, unsigned long) {
    free(p);
}

// Optional exception handler stub
// extern "C" void __sfp_handle_exceptions() {}
#endif

extern "C" {

/// Frame info registration stub (no-op)
void __register_frame_info(void*, void*) {}

/// Pure virtual function call handler
void __cxa_pure_virtual() {
    puts("__cxa_pure_virtual called");
    exit(10);
}

/// Guard functions for static local initialization
int __cxa_guard_acquire(int* o) {
    return *o == 0;
}
int __cxa_guard_release(int* o) {
    return *o = 1;
}
} // extern "C"
