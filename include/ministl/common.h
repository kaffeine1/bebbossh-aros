/*
 * ministl common utilities
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
 * Purpose: Provide common type traits, object base class, and utility
 *          functions for the ministl subset used in ministl.
 *
 * Features:
 *  - __TRAITS macro for defining container traits
 *  - __oo base class with reference counting
 *  - destroy() and construct() helpers for placement new/delete
 *  - Overloaded operator new/delete for placement semantics
 *  - back_insert_iterator for container insertion
 *
 * Notes:
 *  - Copying of __oo is explicitly disabled using = delete
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__COMMON_H__
#define __MINISTL__COMMON_H__

#include <stddef.h>

//==============================================================================
/// Define common type traits for containers
#define __TRAITS(T) \
  typedef T value_type; \
  typedef T& reference; \
  typedef T const& const_reference; \
  typedef T* pointer; \
  typedef T const* const_pointer

//==============================================================================
/// Base class with reference counting
class __oo {
public:
    __oo(__oo const&) = delete;
    __oo& operator=(__oo const&) = delete;

private:
    unsigned long refCount;

protected:
    __oo() : refCount(0) {}
    virtual ~__oo() {}

public:
    unsigned long getRefCount() const { return refCount; }
};

//==============================================================================
/// Destroy overloads for primitive types
inline void destroy(bool*) {}
inline void destroy(char*) {}
inline void destroy(char**) {}
inline void destroy(unsigned char*) {}
inline void destroy(short*) {}
inline void destroy(unsigned short*) {}
inline void destroy(int*) {}
inline void destroy(unsigned int*) {}
inline void destroy(long*) {}
inline void destroy(unsigned long*) {}
inline void destroy(float*) {}
inline void destroy(double*) {}
inline void destroy(void**) {}
inline void destroy(const void**) {}

inline void destroy(const char*) {}
inline void destroy(const char**) {}
inline void destroy(const unsigned char*) {}
inline void destroy(const short*) {}
inline void destroy(const unsigned short*) {}
inline void destroy(const int*) {}
inline void destroy(const unsigned int*) {}
inline void destroy(const long*) {}
inline void destroy(const unsigned long*) {}
inline void destroy(const float*) {}
inline void destroy(const double*) {}

/// Destroy for user-defined types
template <class T>
inline void destroy(T* pointer) {
    pointer->T::~T();
}

//==============================================================================
/// Construct overloads for primitive types
inline void construct(bool* p, bool c) { *p = c; }
inline void construct(char* p, char c) { *p = c; }
inline void construct(wchar_t* p, wchar_t c) { *p = c; }
inline void construct(char** p, char* c) { *p = c; }
inline void construct(unsigned char* p, unsigned char c) { *p = c; }
inline void construct(short* p, short c) { *p = c; }
inline void construct(unsigned short* p, unsigned short c) { *p = c; }
inline void construct(int* p, int c) { *p = c; }
inline void construct(unsigned int* p, unsigned int c) { *p = c; }
inline void construct(long* p, long c) { *p = c; }
inline void construct(unsigned long* p, unsigned long c) { *p = c; }
inline void construct(float* p, float c) { *p = c; }
inline void construct(double* p, double c) { *p = c; }
inline void construct(void** p, void* c) { *p = c; }
inline void construct(const void** p, const void* c) { *p = c; }

//==============================================================================
/// Placement new/delete overloads for GCC
#ifdef __GNUC__
inline void* operator new(size_t, void* p) throw() { return p; }
inline void* operator new[](size_t, void* p) throw() { return p; }
inline void  operator delete(void*, void*) throw() {}
inline void  operator delete[](void*, void*) throw() {}
#endif

//==============================================================================
/// Construct with placement new
template <class T1, class T2>
inline void construct(T1* p, const T2& value) {
    ::new (p) T1(value);
}

//==============================================================================
/// back_insert_iterator for container insertion
template <class Container>
class back_insert_iterator {
protected:
    Container& container;
public:
    back_insert_iterator(Container& x) : container(x) {}
    back_insert_iterator<Container>&
    operator=(const typename Container::value_type& value) {
        container.push_back(value);
        return *this;
    }
    back_insert_iterator<Container>& operator*() { return *this; }
    back_insert_iterator<Container>& operator++() { return *this; }
    back_insert_iterator<Container> operator++(int) { return *this; }
};

#endif // __MINISTL__COMMON_H__
