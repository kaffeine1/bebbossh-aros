/*
 * ministl memory
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
 * Project: ministl
 * Purpose: Provide lightweight map/multimap containers on top of the
 *          pooled mstl::set with pair key/value semantics.
 *
 * Notes:
 *  - Copy-prevention expanded to = delete (no macros)
 *  - Iterators fix operator! to mean "end"
 *  - const begin/end/rbegin/rend return proper const_iterator objects
 * ----------------------------------------------------------------------
 */
#ifndef __MSTL_MEMORY_H__
#define __MSTL_MEMORY_H__

namespace mstl {

template <typename T>
class unique_ptr {
private:
    T* ptr;

public:
    // Constructor
    explicit unique_ptr(T* p = nullptr) : ptr(p) {}

    // Destructor: automatically deletes the owned object
    ~unique_ptr() {
        delete ptr;
    }

    // Disable copy semantics (unique ownership)
    unique_ptr(const unique_ptr&) = delete;
    unique_ptr& operator=(const unique_ptr&) = delete;

    // Enable move semantics
    unique_ptr(unique_ptr&& other) noexcept : ptr(other.ptr) {
        other.ptr = nullptr;
    }

    unique_ptr& operator=(unique_ptr&& other) noexcept {
        if (this != &other) {
            delete ptr;          // free current
            ptr = other.ptr;     // take ownership
            other.ptr = nullptr; // release other's ownership
        }
        return *this;
    }

    // Accessors
    T* get() const { return ptr; }
    T& operator*() const { return *ptr; }
    T* operator->() const { return ptr; }

    operator T*() const { return ptr; }

    // Release ownership without deleting
    T* release() {
        T* tmp = ptr;
        ptr = nullptr;
        return tmp;
    }

    // Replace managed object
    void reset(T* p = nullptr) {
        delete ptr;
        ptr = p;
    }
};

}
#endif // __MSTL_MEMORY_H__
