/*
 * ministl vector
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
 * Purpose: Provide lightweight vector container implementation for the
 *          ministl subset used in ministl.
 *
 * Features:
 *  - __ptr_size: pointer wrapper with size tracking
 *  - __vector: base class managing raw memory and capacity
 *  - vector<T>: templated container with STL-like interface
 *  - push_back, pop_back, resize, iterators
 *
 * Notes:
 *  - Copying of __vector is explicitly disabled using = delete
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__VECTOR_H__
#define __MINISTL__VECTOR_H__

#ifndef MINISTL__COMMON_H
#include <ministl/common.h>
#endif

#include <stdint.h>

namespace mstl {

//==============================================================================
/// Pointer wrapper with size tracking
struct __ptr_size {
    inline __ptr_size(void const* d, unsigned s) : data_((uint8_t*)d), _size(s) {}

    inline uint8_t& operator[](unsigned int idx) { return data_[idx]; }
    inline uint8_t const& operator[](unsigned int idx) const { return data_[idx]; }

    inline uint8_t* begin() const { return data_; }
    inline int size() const { return _size; }
    inline void setSizeValue(int s) { _size = s; }

protected:
    inline __ptr_size(__ptr_size&& o) noexcept {
        data_ = o.data_;
        o.data_ = 0;
        _size = o._size;
        o._size = 0;
    }
    uint8_t* data_;       ///< pointer to the data
    unsigned int _size;   ///< number of parts
};

/**
 * @class __vector
 * @brief Base vector class managing raw memory and capacity.
 */
class __vector : public __ptr_size {
public:
    __vector(__vector const&) = delete;
    __vector& operator=(__vector const&) = delete;

protected:
    unsigned int max_;   ///< maximum number of parts
    unsigned int tSize_; ///< sizeof each part

protected:
    __vector(unsigned int tSize, unsigned int count = 0);
    __vector(__vector&& o) noexcept;
    virtual ~__vector();

    __vector& operator=(__vector&& o);

    inline unsigned int __length() const { return _size * tSize_; }
    inline uint8_t* __begin() const { return data_; }
    inline uint8_t* __end() const { return data_ + __length(); }
    inline uint8_t* __at(unsigned int idx) const { return data_ + idx * tSize_; }
    inline int __inc() { if (!reserve(_size + 1)) return 0; return ++_size; }
    inline int __dec() { return _size > 0 ? --_size : 0; }
    inline void __setCount(unsigned int count) { if (count <= max_) _size = count; }
    inline unsigned int __size() const { return _size; }

public:
    inline unsigned int capacity() const { return max_; }
    inline unsigned int max_size() const { return 0x00ffffff / tSize_; }
    inline unsigned int empty() const { return _size == 0; }
    int reserve(unsigned int nSize);
    int setSize(unsigned int nSize);
    int setSizeZ(unsigned int nSize); // also zeros
    inline void clear() { _size = 0; }
};

//==============================================================================
/// Vector template providing STL-like interface
template<class T>
struct vector : public __vector {
    __TRAITS(T);
    typedef signed int difference_type;
    typedef unsigned int size_type;
    typedef T* iterator;
    typedef T const* const_iterator;
    typedef T* reverse_iterator;
    typedef T const* const_reverse_iterator;

    inline vector(int sz = 0) : __vector(sizeof(T), sz) {}
    inline ~vector() {
        iterator i = begin();
        while (i != end()) {
            destroy(i);
            ++i;
        }
    }

    vector(vector const& o);
    inline vector(vector&& o) noexcept : __vector((__vector&&)o) {}
    vector& operator=(vector const& o);
    inline vector& operator=(vector&& o) { return (vector&)__vector::operator=((__vector&&)o); }

    inline iterator begin() { return (T*)__begin(); }
    inline iterator end() { return (T*)__end(); }
    inline reverse_iterator rbegin() { return (T*)__begin() - 1; }
    inline reverse_iterator rend() { return (T*)__end() - 1; }
    inline const_iterator begin() const { return (T*)__begin(); }
    inline const_iterator end() const { return (T*)__end(); }
    inline const_reverse_iterator rbegin() const { return (T*)__begin() - 1; }
    inline const_reverse_iterator rend() const { return (T*)__end() - 1; }

    int resize(size_type sz, T const& c = T());

    inline T& at(unsigned int idx) { return *(T*)__at(idx); }
    inline T const& at(unsigned int idx) const { return *(T*)__at(idx); }
    inline T& operator[](unsigned int idx) { return at(idx); }
    inline T const& operator[](unsigned int idx) const { return at(idx); }

    inline int push_back(T const& t) {
        unsigned int i = __inc();
        if (!i) return false;
        construct(rend(), t);
        return true;
    }

    inline void pop_back() {
        if (size() > 0) destroy(rend());
        __dec();
    }

    inline unsigned int size() const { return __vector::__size(); }

    inline int operator==(const vector<T>& o) const { return this == &o; }

    inline void __setCount(unsigned int count) {
        reserve(count);
        __vector::__setCount(count);
    }
};

//==============================================================================
/// Copy constructor
template<class T>
vector<T>::vector(vector<T> const& o) : __vector(sizeof(T), o.__size()) {
    if (size()) {
        iterator i = end();
        const_iterator j = o.end();
        while (--i >= begin()) {
            construct(i, *--j);
        }
    }
}

//==============================================================================
/// Copy assignment
template<class T>
vector<T>& vector<T>::operator=(vector<T> const& o) {
    __vector::reserve(o.size());
    iterator i = begin();
    const_iterator j = o.begin();
    while (i != end() && j != o.end()) {
        destroy(i);
        construct(i, *j);
        ++i;
        ++j;
    }
    while (i != end()) {
        destroy(i);
        ++i;
    }
    __vector::__setCount(o.size());
    while (i != end() && j != o.end()) {
        construct(i, *j);
        ++i;
        ++j;
    }
    return *this;
}

//==============================================================================
/// Resize implementation
template<class T>
int vector<T>::resize(size_type sz, T const& c) {
    difference_type d = sz - size();
    iterator i = end();
    if (d < 0) {
        while (d++ < 0) destroy(--i);
        return true;
    }
    if (d > 0) {
        if (!reserve(sz)) return false;
        while (d-- > 0) construct(i++, c);
    }
    return true;
}

typedef vector<int> bit_vector;

} // namespace mstl

/// Placement new overload for mstl::vector
template<class T>
void* operator new(size_t s, mstl::vector<T>* v) {
    return v;
}

#endif // __MINISTL__VECTOR_H__
