/*
 * ministl algorithms
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
 * Purpose: Provide lightweight STL-style algorithms for use in the
 *          ministl library and Amiga projects.
 *
 * Features:
 *  - back_inserter helper
 *  - binary_search with custom comparators
 *  - replace, replace_if, replace_copy, replace_copy_if
 *  - remove, remove_if, remove_copy, remove_copy_if
 *  - find, find_if
 *  - sort, fill, advance, copy
 *  - adjacent_find, adjacent_difference
 *  - accumulate, min, max
 *
 * Notes:
 *  - Designed as a minimal STL subset for embedded/Amiga contexts
 *  - Integrates with mstl::set, mstl::vector, and functional objects
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__ALGO_H__
#define __MINISTL__ALGO_H__

#ifndef MINISTL__COMMON_H
#include <ministl/common.h>
#endif

#ifndef __MINISTL__SET_H__
#include <ministl/func.h>
#endif

#ifndef __MINISTL__SET_H__
#include <ministl/set.h>
#endif

namespace mstl {

/**
 * @brief Create a back_insert_iterator for a container.
 */
template<class T> back_insert_iterator<T> back_inserter(T& t) {
  return back_insert_iterator<T>(t);
}

/**
 * @brief Internal binary search helper.
 */
template<class R, class O>
R __binary_search(R first, R last, O const& o) {
  long d0 = last - first;
  long d = 1;
  while (d < d0)
    d <<= 1;
  d >>= 1;
  long x = d;
  while (d > 0) {
    if (x < d0 && o(*(x + first)))
      x += d;
    else
      x -= d;
    d >>= 1;
  }
  if (o(*first))
    return first;
  return last;
}

/**
 * @brief Wrap a unary function pointer.
 */
template<class P, class F> struct pointer_to_unary_function : public unary_function<P, F> {
  F (*x)(P);
  pointer_to_unary_function(F(*x_)(P)) : x(x_) {}
  inline int operator()(P const& p) const { return x(p); }
};

template<class Arg1, class Result>
inline pointer_to_unary_function<Arg1, Result> ptr_fun(Result(*x)(Arg1)) {
  return pointer_to_unary_function<Arg1, Result>(x);
}

/**
 * @brief Wrap a binary function pointer.
 */
template<class P, class Q, class F> struct pointer_to_binary_function : public binary_function<P, Q, F> {
  F (*x)(P, Q);
  pointer_to_binary_function(pointer_to_binary_function const& o) : x(o.x) {}
  pointer_to_binary_function& operator=(pointer_to_binary_function const& o) { x = o.x; return *this; }
  pointer_to_binary_function(F(*x_)(P, Q)) : x(x_) {}
  inline int operator()(P const& p, Q const& q) const { return x(p, q); }
};

template<class Arg1, class Arg2, class Result>
inline pointer_to_binary_function<Arg1, Arg2, Result> ptr_fun(Result(*x)(Arg1, Arg2)) {
  return pointer_to_binary_function<Arg1, Arg2, Result>(x);
}

/**
 * @brief Binary search with comparator.
 */
template<class R, class T, class O>
inline R binary_search(R first, R last, T const& t, O const& o) {
  return __binary_search(first, last, bind2nd(ptr_fun(o), t));
}

/**
 * @brief Binary search with equality comparator.
 */
template<class R, class T>
inline R binary_search(R first, R last, T const& t) {
  return __binary_search(first, last, bind2nd(equal_to<T>(), t));
}

// --- replace, remove, find, sort, fill, copy, adjacent_find, adjacent_difference, accumulate, min, max ---
// (Implementation unchanged, see original code)

template<class ForwardIterator, class T>
void replace(ForwardIterator first, ForwardIterator last, const T& old_value, const T& new_value) {
  for (; first != last; ++first)
    if (*first == old_value)
      *first = new_value;
}

template<class ForwardIterator, class Predicate, class T>
void replace_if(ForwardIterator first, ForwardIterator last, Predicate pred, const T& new_value) {
  for (; first != last; ++first)
    if (pred(*first))
      *first = new_value;
}

template<class InputIterator, class OutputIterator, class T>
OutputIterator replace_copy(InputIterator first, InputIterator last, OutputIterator result, const T& old_value,
    const T& new_value) {
  for (; first != last; ++first, ++result)
    *result = *first == old_value ? new_value : *first;
  return result;
}

template<class Iterator, class OutputIterator, class Predicate, class T>
OutputIterator replace_copy_if(Iterator first, Iterator last, OutputIterator result, Predicate pred, const T& new_value) {
  for (; first != last; ++first, ++result)
    *result = pred(*first) ? new_value : *first;
  return result;
}

template<class InputIterator, class OutputIterator, class T>
OutputIterator remove_copy(InputIterator first, InputIterator last, OutputIterator result, const T& value) {
  for (; first != last; ++first)
    if (*first != value) {
      *result = *first;
      ++result;
    }
  return result;
}

template<class InputIterator, class OutputIterator, class Predicate>
OutputIterator remove_copy_if(InputIterator first, InputIterator last, OutputIterator result, Predicate pred) {
  for (; first != last; ++first)
    if (!pred(*first)) {
      *result = *first;
      ++result;
    }
  return result;
}

template<class InputIterator, class T>
InputIterator find(InputIterator first, InputIterator last, const T& value) {
  while (first != last && *first != value)
    ++first;
  return first;
}

template<class InputIterator, class Predicate>
InputIterator find_if(InputIterator first, InputIterator last, Predicate pred) {
  while (first != last && !pred(*first))
    ++first;
  return first;
}

template<class ForwardIterator, class T>
ForwardIterator remove(ForwardIterator first, ForwardIterator last, const T& value) {
  first = find(first, last, value);
  if (first == last)
    return first;
  else {
    ForwardIterator next = first;
    return remove_copy(++next, last, first, value);
  }
}

template<class ForwardIterator, class Predicate>
ForwardIterator remove_if(ForwardIterator first, ForwardIterator last, Predicate pred) {
  first = find_if(first, last, pred);
  if (first == last)
    return first;
  else {
    ForwardIterator next = first;
    return remove_copy_if(++next, last, first, pred);
  }
}

template<class InputIterator, class EqualityComparable, class Size>
void count(InputIterator first, InputIterator last, const EqualityComparable & e, Size& n) {
  while (first != last) {
    if (*first == e)
      ++n;
    ++first;
  }
}

template<class InputIterator, class EqualityComparable>
typename InputIterator::difference_type count(InputIterator first, InputIterator last, const EqualityComparable& value) {
  typename InputIterator::difference_type n = 0;
  return count(first, last, value, n);
}

template<class I, class O, class T>
void __sort(I first, I last, O const &, T &) {
  set<T, O> s;
  for (I i = first; i != last; ++i) {
    s.insert(*i);
  }
  typename set<T, O>::iterator e = s.end();
  for (typename set<T, O>::iterator j = s.begin(); j != e; ++j, ++first)
    *first = *j;
}

template<class I, class O> inline void sort(I first, I last, O const & o) {
  __sort(first, last, o, *first);
}

template<class I, class T> inline void __sort(I first, I last, T const &) {
  sort(first, last, less<T> ());
}

template<class I> inline void sort(I first, I last) {
  __sort(first, last, *first);
}

template<class I, class O> void fill(I first, I last, O value) {
  while (first != last) {
    *first = value;
    ++first;
  }
}

template<class I, class D> inline void advance(I & i, D d) {
  i += d;
}

template<class I, class O> O copy(I first, I last, O result) {
  while (first != last) {
    *result = *first;
    ++first;
    ++result;
  }
  return result;
}

template<class I, class T>
I __adjacent_find(I first, I last, T) {
  I i = first;
  while (first != last) {
    if (*++i == *first)
      return first;
    ++first;
  }
  return last;
}

template<class I> inline I adjacent_find(I first, I last) {
  return __adjacent_find(first, last, *first);
}

template<class I, class BinOp, class T>
I __adjacent_find(I first, I last, BinOp binary_op, T) {
  I i = first;
  while (first != last) {
    if (binary_op(*++i, *first))
      return first;
    ++first;
  }
  return last;
}

template<class I, class BinOp> inline I adjacent_find(I first, I last, BinOp binary_op) {
  return __adjacent_find(first, last, binary_op, *first);
}

template<class I, class O, class T>
O __adjacent_difference(I first, I last, O result, T t) {
  *result = t;
  while (++first != last) {
    T t2 = *first;
    *++result = t2 - t;
    t = t2;
  }
  return result;
}

template<class I, class O> inline O adjacent_difference(I first, I last, O result) {
  return __adjacent_difference(first, last, result, *first);
}

template<class I, class O, class BinOp, class T>
O __adjacent_difference(I first, I last, O result, BinOp binary_op, T t) {
  *result = t;
  while (++first != last) {
    T t2 = *first;
    *++result = binary_op(t2, t);
    t = t2;
  }
  return result;
}

template<class I, class O, class BinOp> inline O adjacent_difference(I first, I last, O result, BinOp binary_op) {
  return __adjacent_difference(first, last, result, binary_op, *first);
}

template<class I, class T>
T accumulate(I first, I last, T init) {
  for (; first != last; ++first)
    init = init + *first;
  return init;
}

// ... (all other algorithm templates remain as in your original code)

template<class T> const T& min(const T& a, const T& b) {
  return a <= b ? a : b;
}

template<class T> const T& max(const T& a, const T& b) {
  return a >= b ? a : b;
}

template<class T, class BinaryPredicate>
const T& min(const T& a, const T& b, BinaryPredicate comp);

} // namespace mstl

#endif // __MINISTL__ALGO_H__
