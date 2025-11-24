/*
 * ministl allocator
 * Copyright (C) 1998, 2024-2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide lightweight memory page and pool allocator classes
 *          for efficient block allocation in the ministl library.
 *
 * Features:
 *  - __mem_page: manages fixed-size blocks in a page
 *  - __mem_pool: high-level pool allocator using linked pages
 *  - Inline helpers for block indexing and state checks
 *
 * Notes:
 *  - Copying of allocator classes is explicitly disabled using = delete
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__ALLOC_H__
#define __MINISTL__ALLOC_H__

#ifndef MINISTL__COMMON_H
#include <ministl/common.h>
#endif

namespace mstl {

/**
 * @class __mem_page
 * @brief Represents a memory page containing fixed-size blocks.
 */
class __mem_page {
public:
    __mem_page(__mem_page const&) = delete;
    __mem_page& operator=(__mem_page const&) = delete;

    friend class __mem_pool;

private:
    __mem_page* next;   ///< Next page in list
    __mem_page* prev;   ///< Previous page in list
    unsigned int const n;   ///< Total count of blocks
    unsigned int const sz;  ///< Size of each block
    unsigned int qc;        ///< Count in queue
    char* base;             ///< Base memory pointer
    char* last;             ///< Last free block
    char* queue;            ///< First free block in queue

public:
    __mem_page(unsigned int sz_, unsigned int n_);
    virtual ~__mem_page();

    inline unsigned int prt2n(char const* p) const;
    inline char* prt2n(unsigned int n) const;
    inline int full() const;
    inline int empty() const;
    inline unsigned int blocksize() const;

    virtual char* alloc();
    virtual __mem_page* free(char*);
};

/**
 * @class __mem_pool
 * @brief High-level memory pool managing multiple pages.
 */
class __mem_pool {
public:
    __mem_pool(__mem_pool const&) = delete;
    __mem_pool& operator=(__mem_pool const&) = delete;

private:
    unsigned int const sz; ///< Block size
    unsigned int n;        ///< Number of blocks
    __mem_page* akt;       ///< Current active page

public:
    __mem_pool(int sz, unsigned int n = 0);
    ~__mem_pool();

    /// Allocate a block
    char* alloc();

    /// Free a block
    void free(void*);

    /// Release all pages
    void release_all();
};

// --- Inline helpers ---

inline unsigned int __mem_page::prt2n(char const* p) const {
    return (unsigned int)(((long)(p - base) - 4) / sz);
}

inline char* __mem_page::prt2n(unsigned int i) const {
    return 4 + (base + i * sz);
}

inline int __mem_page::full() const {
    return (last == base) && qc == 0;
}

inline int __mem_page::empty() const {
    return (last - base) / sz + qc == n;
}

inline unsigned int __mem_page::blocksize() const {
    return sz;
}

} // namespace mstl

#endif // __MINISTL__ALLOC_H__
