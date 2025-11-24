/*
 * ministl functional utilities
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
 * Purpose: Provide functional object templates and adapters for the
 *          ministl subset used in ministl.
 *
 * Features:
 *  - unary_function and binary_function base templates
 *  - Comparison functors: equal_to, less, greater
 *  - Logical functor: logical_and
 *  - Function adapters: binary_negate, bind1st, bind2nd
 *  - Function composition: binary_compose, compose2
 *
 * Notes:
 *  - Designed as a minimal STL functional subset for embedded/Amiga contexts
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__FUNC_H__
#define __MINISTL__FUNC_H__

#ifndef MINISTL__COMMON_H
#include <ministl/common.h>
#endif

namespace mstl {

//==============================================================================
/// Base class for unary functions
template<class T, class R>
struct unary_function {
    typedef T argument_type;
    typedef R result_type;
};

//==============================================================================
/// Base class for binary functions
template<class T1, class T2, class R>
struct binary_function {
    typedef T1 first_argument_type;
    typedef T2 second_argument_type;
    typedef R result_type;
};

//==============================================================================
/// Equality comparison functor
template<class T>
struct equal_to : public binary_function<T, T, int> {
    int operator()(T const& a, T const& b) const { return a == b; }
};

//==============================================================================
/// Less-than comparison functor
template<class T>
struct less : public binary_function<T, T, int> {
    int operator()(T const& a, T const& b) const { return a < b; }
};

//==============================================================================
/// Greater-than comparison functor
template<class T>
struct greater : public binary_function<T, T, int> {
    int operator()(T const& a, T const& b) const { return a > b; }
};

//==============================================================================
/// Logical AND functor
template<class T>
struct logical_and : public binary_function<T, T, int> {
    typedef T argument_type;
    typedef int result_type;
    int operator()(T const& a, T const& b) const { return a && b; }
};

//==============================================================================
/// Negates a binary predicate
template<typename O>
struct binary_negate : public binary_function<typename O::first_argument_type,
                                              typename O::second_argument_type, int> {
    O o;
    binary_negate() : o() {}
    binary_negate(O const& o_) : o(o_) {}
    int operator()(const typename O::first_argument_type& a,
                   const typename O::second_argument_type& b) const {
        return !o(a, b);
    }
};

/// Helper to create binary_negate
template<class O>
inline binary_negate<O> not2(O const& pred) {
    return binary_negate<O>(pred);
}

//==============================================================================
/// Binds first argument of a binary function
template<class O>
struct binder1st {
    O o;
    typename O::first_argument_type t;
    binder1st(O const& o_, const typename O::first_argument_type& t_) : o(o_), t(t_) {}
    typename O::result_type operator()(const typename O::first_argument_type& b) const {
        return o(t, b);
    }
};

/// Helper to create binder1st
template<class O, class T>
inline binder1st<O> bind1st(O const& o, T const& t) {
    return binder1st<O>(o, t);
}

//==============================================================================
/// Binds second argument of a binary function
template<class O>
struct binder2nd {
    O o;
    typename O::second_argument_type t;
    binder2nd(binder2nd const& x) : o(x.o), t(x.t) {}
    binder2nd& operator=(binder2nd const& x) { o = x.o; t = x.t; return *this; }
    binder2nd(O const& o_, const typename O::second_argument_type& t_) : o(o_), t(t_) {}
    typename O::result_type operator()(const typename O::second_argument_type& a) const {
        return o(a, t);
    }
};

/// Helper to create binder2nd
template<class O, class T>
inline binder2nd<O> bind2nd(O const& o, T const& t) {
    return binder2nd<O>(o, t);
}

//==============================================================================
/// Compose two unary functions with a binary function
template<class C, class V1, class V2>
struct binary_compose : public binary_function<typename C::result_type,
                                               typename V1::argument_type,
                                               typename V2::argument_type> {
    C c;
    V1 v1;
    V2 v2;
    binary_compose(C const& _c = C(), V1 const& _v1 = V1(), V2 const& _v2 = V2())
        : c(_c), v1(_v1), v2(_v2) {}
    typename C::result_type operator()(const typename V1::argument_type& a,
                                       const typename V2::argument_type& b) const {
        return c(v1(a), v2(b));
    }
    typename C::result_type operator()(const typename V1::argument_type& a) const {
        return c(v1(a), v2(a));
    }
};

/// Helper to create binary_compose
template<class C, class V1, class V2>
binary_compose<C, V1, V2> compose2(C const&, V1 const&, V2 const&) {
    return binary_compose<C, V1, V2>();
}

} // namespace mstl

#endif /* __MINISTL__FUNC_H__ */
