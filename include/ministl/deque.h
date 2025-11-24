/*
 * ministl deque
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
 * Purpose: Provide a lightweight deque container implementation for
 *          the ministl subset used in ministl.
 *
 * Features:
 *  - Dynamic double-ended queue using mstl::vector and __mem_pool
 *  - push_back and pop_back operations
 *  - Iterators and const_iterators for traversal
 *  - Reverse iterators for reverse traversal
 *
 * Notes:
 *  - Uses __mem_pool for efficient block allocation
 *  - Copy constructor is declared but must be defined separately
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__DEQUE_H__
#define __MINISTL__DEQUE_H__

#include <ministl/alloc.h>
#include <ministl/algo.h>
#include <ministl/vector.h>

namespace mstl {

/**
 * @class deque
 * @brief Double-ended queue container.
 *
 * Provides push_back/pop_back operations and iterator support.
 * Internally uses mstl::vector of void* and __mem_pool for
 * memory management.
 */
template <class T>
class deque {
    typedef vector<void*> __vt;
    __vt v;
    unsigned int head;
    __mem_pool mp;

    inline T* __make_node() { return (T*)mp.alloc(); }
    inline void __free_node(T* p) { mp.free(p); }

public:
    __TRAITS(T);
    typedef signed int difference_type;
    typedef unsigned int size_type;

    /// Default constructor
    inline deque() : v(), head(0), mp(sizeof(void*) * 2) {}

    /// Construct with initial size
    inline deque(unsigned int sz) : v(sz), head(0), mp(sizeof(void*) * 2) {
        fill(v.begin(), v.end(), 0);
    }

    /// Copy constructor (defined elsewhere)
    deque(deque const&);

    /// Push element at back
    inline int push_back(T const& t) {
        T* p = __make_node();
        if (!p) return false;
        if (!v.push_back(p)) { __free_node(p); return false; }
        *v.rend() = p;
        construct(p, t);
        return true;
    }

    /// Pop element from back
    inline void pop_back() {
        if (size() > 0) {
            T** p = (T**)v.rend();
            destroy(*p);
            __free_node(*p);
            *p = 0;
            v.pop_back();
        }
    }

    /// Return number of elements
    inline unsigned int size() const { return v.size() - head; }

    /// Return maximum size
    inline unsigned int max_size() const { return v.max_size(); }

    /// Check if empty
    inline unsigned int empty() const { return v.size() - head == 0; }

    /**
     * @class iterator
     * @brief Iterator for deque.
     */
    class iterator {
        __vt::iterator i;
    public:
        iterator() : i(0) {}
        iterator(T** t) : i((void**)t) {}
        iterator(iterator const& o) : i(o.i) {}
        iterator& operator=(iterator const& o) { i = o.i; return *this; }
        T& operator*() { return **(T**)i; }
        T const& operator*() const { return **(T**)i; }
        iterator& operator++() { ++i; return *this; }
        iterator& operator--() { --i; return *this; }
        iterator operator++(int) { iterator t(*this); ++i; return t; }
        iterator operator--(int) { iterator t(*this); --i; return t; }
        int operator!=(const iterator& o) const { return i != o.i; }
    };

    /**
     * @class const_iterator
     * @brief Const iterator for deque.
     */
    class const_iterator {
        __vt::iterator i;
    public:
        const_iterator() : i(0) {}
        const_iterator(T const** t) : i((void**)t) {}
        T const& operator*() const { return **(T**)i; }
        const_iterator& operator++() { ++i; return *this; }
        const_iterator& operator--() { --i; return *this; }
        const_iterator operator++(int) { const_iterator t(*this); ++i; return t; }
        const_iterator operator--(int) { const_iterator t(*this); --i; return t; }
        int operator!=(const const_iterator& o) const { return i != o.i; }
    };

    typedef iterator reverse_iterator;
    typedef const_iterator const_reverse_iterator;

    inline iterator begin() { return (T**)v.begin() + head; }
    inline iterator end() { return (T**)v.end(); }
    inline reverse_iterator rbegin() { return (T**)v.rbegin() + head; }
    inline reverse_iterator rend() { return (T**)v.rend(); }
    inline const_iterator begin() const { return begin(); }
    inline const_iterator end() const { return end(); }
    inline const_reverse_iterator rbegin() const { return rbegin(); }
    inline const_reverse_iterator rend() const { return rend(); }
};

} // namespace mstl

#endif // __MINISTL__DEQUE_H__
