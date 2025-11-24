/*
 * ministl string
 * Copyright (C) 1998, 2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide lightweight string container built on mstl::vector
 *          with C-style semantics for char and wchar_t.
 *
 * Features:
 *  - Constructors from literals, lengths, and other strings
 *  - Comparison operators (<, ==, !=)
 *  - Assignment and concatenation
 *  - c_str(), length(), find(), substr()
 *  - Typedefs for cstring, wstring, bstring
 *
 * Notes:
 *  - Copying is supported via vector<T>, no DONOTCOPY macro needed
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__STRING_H__
#define __MINISTL__STRING_H__

#ifndef MINISTL__VECTOR_H
#include <ministl/vector.h>
#endif

#include <string.h>
#include <wchar.h>

#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

// wide‑char overloads
inline int strlen(wchar_t const* s) { return wcslen(s); }
inline wchar_t* strcpy(wchar_t* dest, wchar_t const* src) { return wcscpy(dest, src); }
inline wchar_t* strncpy(wchar_t* dest, wchar_t const* src, size_t count) { return wcsncpy(dest, src, count); }
inline int strcmp(wchar_t const* dest, wchar_t const* src) { return wcscmp(dest, src); }
inline wchar_t const* strstr(wchar_t const* string, wchar_t const* part) { return wcsstr(string, part); }

namespace mstl {

//==============================================================================
/// string<T> built on mstl::vector<T>
template<class T>
struct string : public vector<T> {
    inline operator T const*() const { return vector<T>::begin(); }
    inline operator T*() { return vector<T>::begin(); }

    inline string() : vector<T>(1) { vector<T>::at(0) = 0; }
    inline string(unsigned int len, T init) : vector<T>(len) {
        for (unsigned int i = 0; i < len; ++i) vector<T>::at(i) = init;
    }
    inline string(T const* const t) : vector<T>(strlen(t) + 1) {
        for (unsigned int i = 0; i < vector<T>::size(); ++i) vector<T>::at(i) = t[i];
    }
    inline string(string<T> const& o) : vector<T>(o) {}
    string(string<T> const& a, string<T> const& b);

    inline int operator<(string<T> const& o) const { return strcmp(this->begin(), o.begin()) < 0; }
    inline int operator==(string<T> const& o) const { return strcmp(this->begin(), o.begin()) == 0; }
    inline int operator!=(string<T> const& o) const { return strcmp(this->begin(), o.begin()) != 0; }

    inline string& operator=(T const* const ptr) {
        unsigned int len = strlen(ptr) + 1;
        vector<T>::reserve(len);
        vector<T>::__setCount(len);
        strcpy(vector<T>::begin(), ptr);
        return *this;
    }
    inline string& operator=(string<T> const& o) {
        vector<T>::operator=(o);
        return *this;
    }
    inline string& operator+=(string<T> const& o) { return *this = *this + o; }

    inline T const* c_str() const { return vector<T>::begin(); }
    inline size_t length() const { return vector<T>::size() - 1; }

    inline size_t find(T const* s, size_t pos = 0) const {
        if (pos > length()) return (size_t)-1;
        T const* found = strstr(this->begin(), s);
        if (!found) return (size_t)-1;
        return found - this->begin();
    }

    inline string substr(size_t pos = 0, size_t n = npos) const {
        if (pos > length()) return string<T>();
        size_t len = length() - pos;
        if (n > len) n = len;
        string<T> r(n + 1, 0);
        strncpy((T*)r.begin(), this->begin() + pos, n);
        return r;
    }

    static size_t npos;
    static string toString(long long ll);
};

template<class T> size_t string<T>::npos = (size_t)-1;

//==============================================================================
// operators
template<class T>
inline string<T> operator+(string<T> const& a, T const* const b) { return a + string<T>(b); }

template<class T>
inline string<T> operator+(T const* const a, string<T> const& b) { return string<T>(a) + b; }

template<class T>
inline string<T> operator+(string<T> const& a, string<T> const& b) { return string<T>(a, b); }

template<class T>
inline int operator==(string<T> const& a, T const* b) { return 0 == strcmp(a.begin(), b); }

//==============================================================================
// typedefs
typedef string<char> cstring;
typedef string<wchar_t> wstring;

#ifdef UNICODE
typedef wstring bstring;
#else
typedef cstring bstring;
#endif

} // namespace mstl

#endif // __MINISTL__STRING_H__
