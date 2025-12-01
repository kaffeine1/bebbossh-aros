/*
 * ministl vector implementation
 * Copyright (C) 1998-2011 BebboSoft - Franke und Fischell GbR,
 * updated 2024-2025 by Stefan Franke <stefan@franke.ms>
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
 * Project: ministl
 * Module: ministl/vector.cpp
 *
 * Purpose:
 *  - Provide a lightweight STL-like vector implementation
 *  - Support dynamic resizing, zero-initialization, and move semantics
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - `reserve()` expands capacity but never shrinks
 *  - `setSize()` adjusts logical size, `setSizeZ()` zero-fills new elements
 *  - Implements move constructor and move assignment for efficiency
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <stdlib.h>
#include <string.h>
#include <ministl/vector.h>

namespace mstl {

//=========================================================================
__vector::__vector(unsigned int tSize, unsigned int count) :
		__ptr_size(count ? (uint8_t*) malloc(tSize * count) : 0, count), max_(count), tSize_(tSize) {
	if (!data_)
		_size = max_ = 0;
}

__vector::__vector(__vector &&o) noexcept : __ptr_size((__ptr_size &&) o), max_(o.max_), tSize_(o.tSize_){
}

__vector::~__vector() {
	if (data_)
		free(data_);
}

//=========================================================================
// Anzahl der Elemente ändern, macht aber nur größer!
int __vector::reserve(unsigned int nMax) {
	if (nMax > max_) {
		uint8_t *t = (uint8_t*) realloc(data_, nMax * tSize_);
		if (0 == t)
			return false;
		data_ = t;
	}
	max_ = nMax;
	return true;
}

int __vector::setSize(unsigned int nSize) {
	if (reserve(nSize)) {
		_size = nSize;
		return true;
	}
	return false;
}

int __vector::setSizeZ(unsigned int nSize) {
	if (reserve(nSize)) {
		int zeroes = nSize - _size;
		if (zeroes > 0) {
			memset(data_ + _size * tSize_, 0, zeroes * tSize_);
		}
		_size = nSize;
		return true;
	}
	return false;
}

__vector & __vector::operator=(__vector && o) {
	free(data_);
	data_ = o.data_;
	_size = o._size;
	max_ = o.max_;
	o.data_ = 0;
	o._size = 0;
	o.max_ = 0;
	return *this;
}

} // end mstl
