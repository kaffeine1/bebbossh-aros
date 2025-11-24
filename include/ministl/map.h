/*
 * ministl map
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
 * Purpose: Provide lightweight map/multimap containers on top of the
 *          pooled mstl::set with pair key/value semantics.
 *
 * Notes:
 *  - Copy-prevention expanded to = delete (no macros)
 *  - Iterators fix operator! to mean "end"
 *  - const begin/end/rbegin/rend return proper const_iterator objects
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__MAP_H__
#define __MINISTL__MAP_H__

#ifndef __MINISTL__SET_H__
#include <ministl/set.h>
#endif

namespace mstl {

//==============================================================================
// pair
//==============================================================================
template<class A, class B>
struct pair {
    typedef A first_pair_type;
    typedef B second_pair_type;

    A first;
    B second;

    pair(A const& a, B const& b) : first(a), second(b) {}
    pair(pair const& p) : first(p.first), second(p.second) {}
    pair& operator=(pair const& p) { first = p.first; second = p.second; return *this; }
};

template<class A, class B>
inline int operator<(const pair<A, B>& a, const pair<A, B>& b) {
    if (a.first == b.first) return a.second < b.second;
    return a.first < b.first;
}

template<class A, class B>
inline int operator==(const pair<A, B>& a, const pair<A, B>& b) {
    if (a.first != b.first) return false;
    return a.second == b.second;
}

template<class A, class B>
inline int operator!=(const pair<A, B>& a, const pair<A, B>& b) {
    return !(a == b);
}

template<class A, class B>
inline pair<A, B> make_pair(const A& a, const B& b) {
    return pair<A, B>(a, b);
}

//==============================================================================
// pair1st - comparator wrapper focusing on first element of pair
//==============================================================================
template<class P>
class pair1st {
public:
    pair1st(pair1st const&) = delete;
    pair1st& operator=(pair1st const&) = delete;

    typename P::first_pair_type f;

    pair1st(P const& p) : f(p.first) {}
    pair1st(const typename P::first_pair_type& f_) : f(f_) {}
};

template<class P>
inline int operator<(const pair1st<P>& a, const pair1st<P>& b) {
    return a.f < b.f;
}

//==============================================================================
// map
//==============================================================================
template<class K, class V, class L = less<pair1st<pair<K, V> > > >
class map : public set<pair<K, V>, L> {
    typedef set<pair<K, V>, L> super;

public:
    map(map const&) = delete;
    map& operator=(map const&) = delete;

    struct leaf : public super::Leaf {
        inline leaf(const pair<K, V>& t) : super::Leaf(t) {}
    };

    struct iterator : public super::iterator {
        inline iterator(leaf* l) : super::iterator(l) {}
        inline iterator(const typename super::iterator& i) : super::iterator(i) {}

        int operator==(const iterator& si) const {
            leaf* l = (leaf*)this->n;
            leaf* r = (leaf*)((iterator*)&si)->n;
            if (!l) return !r;
            if (!r) return false;
            return ((leaf*)this->n)->t.first == (*si).first;
        }
        inline int operator!=(const iterator& si) const { return !this->operator==(si); }

        inline iterator& operator++() { return (iterator&)super::iterator::operator++(); }
        inline iterator operator++(int i) { return (iterator&)super::iterator::operator++(i); }
    };

    struct const_iterator : public super::const_iterator {
        inline const_iterator(leaf* l) : super::const_iterator(l) {}

        int operator==(const typename super::const_iterator& si) const {
            leaf* l = (leaf*)this->n;
            leaf* r = (leaf*)((const_iterator*)&si)->n;
            if (!l) return !r;
            if (!r) return false;
            return ((leaf*)this->n)->t.first == (*si).first;
        }
        inline int operator!=(const typename super::const_iterator& si) const { return !this->operator==(si); }
    };

    inline map() : super() {}

    iterator insert(pair<K, V> const& p) {
        return (leaf*)super::__insert(p);
    }
    iterator insert(K const& k, V const& v) {
        return (leaf*)super::__insert(make_pair(k, v));
    }

    const_iterator find(pair<K, V> const& p) const {
        return (leaf*)super::__find(p);
    }
    const_iterator find(K const& k) const {
        V v;
        return (leaf*)super::__find(make_pair(k, v));
    }

    iterator find(pair<K, V> const& p) {
        return (leaf*)super::__find(p);
    }
    iterator find(K const& k) {
        V v;
        return (leaf*)super::__find(make_pair(k, v));
    }

    int erase(pair<K, V> const& p) { return super::erase(p); }
    int erase(K const& k) {
        V v;
        return super::erase(make_pair(k, v));
    }
};

//==============================================================================
// multimap
//==============================================================================
template<class K, class V, class L = less<pair1st<pair<K, V> > > >
class multimap : public map<K, V, L> {
    typedef map<K, V, L> super;

public:
    multimap(multimap const&) = delete;
    multimap& operator=(multimap const&) = delete;

    inline multimap() : map<K, V, L>() {}

    inline typename super::iterator insert(pair<K, V> const& p) {
        return __insert(p);
    }
    inline typename super::iterator insert(K const& k, V const& v) {
        return insert(make_pair(k, v));
    }
    inline typename super::iterator find(K const& k) const {
        V v;
        return find(make_pair(k, v));
    }
    inline typename super::iterator find(pair<K, V> const& p) const {
        return __find(p);
    }

    // Provided by underlying set specialization if needed:
    typename super::leaf* __insert(pair<K, V> const& p);
    typename super::leaf* __find(pair<K, V> const& p) const;
};

} // namespace mstl

#endif // __MINISTL__MAP_H__
