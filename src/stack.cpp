/*
 * bebbossh - index and socket utility classes
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
 * Purpose: Provide dynamic index management and socket cleanup helpers
 *
 * Features:
 *  - __Index class for slot-based storage with add/remove/replace operations
 *  - Automatic resizing of internal array with memory checks
 *  - WithSocket RAII-style wrapper for safe socket closure
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS; explicit memory allocation and error logging included.
 *
 * Author's intent:
 *  Supply maintainable utility classes to support channel/session management
 *  with robust memory handling and predictable socket lifecycle.
 * ----------------------------------------------------------------------
 */
#include <proto/socket.h>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stack.h>

#include <log.h>

__Index::__Index(uint32_t max_)
 : data(0), max(max_), count(0) {
	if (max) {
		data = (void **)malloc(sizeof(void*) * max);
		if (!data) {
			logme(L_ERROR, "out of memory for %ld bytes", sizeof(void*) * max);
			exit(10);
		}
		memset(data, 0, sizeof(void*) * max);
	}
}

__Index::~__Index() {
	free(data);
}

uint32_t __Index::add(uint32_t const index, void *t) {
	if (index >= max) {
		uint32_t nmax = index + 8;
		data = (void **)realloc(data, sizeof(void*) * nmax);
		if (!data) {
			logme(L_ERROR, "out of memory for %ld bytes", sizeof(void*) * nmax);
			exit(10);
		}
		memset(data + max, 0, sizeof(void*) * (nmax - max));
		max = nmax;
	}
	if (data[index]) {
		logme(L_ERROR, "slot already used: %ld", index);
		exit(10);
	}
	data[index] = t;
	if (t) ++count;
	return index;
}

void * __Index::remove(uint32_t const index) {
	if (index < max) {
		void * t = data[index];
		data[index] = 0;
		if (t) --count;
		return t;
	}
	return 0;
}

void * __Index::replace(uint32_t const index, void * t) {
	if (index < max) {
		void * r = data[index];
		data[index] = t;
		if (t) ++count;
		if (r) --count;
		return r;
	}
	return 0;
}

void* __Index::operator[](uint32_t const index) const {
	if (index < max) {
		return data[index];
	}
	return 0;
}

uint32_t __Index::getFreeIndex() const {
	uint32_t index = 0;
	for(;index < max; ++ index) {
		if (data[index] == 0)
			break;
	}
	return index;
}

WithSocket::~WithSocket() {
	__close();
}

void WithSocket::__close() {
	if (open) {
		logme(L_DEBUG, "CloseSocket(%ld)", sockFd);
		CloseSocket(sockFd);
		open = false;
	}
}
