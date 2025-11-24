/*
 * ministl set (balanced binary tree)
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
 * Purpose: Provide a lightweight set container backed by a pooled,
 *          doubly-threaded binary search tree for the ministl subset.
 *
 * Notes:
 *  - Copying disabled via = delete for internal tree and leaf types
 *  - All node allocations use __mem_pool::alloc with placement new
 *  - All frees call explicit destructor + __mem_pool::free
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__SET_H__
#define __MINISTL__SET_H__

#ifndef MINISTL__COMMON_H
#include <ministl/common.h>
#endif

#ifndef __ALLOC_H__
#include <ministl/alloc.h>
#endif

#ifndef __MINISTL__FUNC_H__
#include <ministl/func.h>
#endif

namespace mstl {

// -----------------------------------------------------------------------------
// Leaf node
// -----------------------------------------------------------------------------
class __Leaf {
    friend class __Tree;

public:
    __Leaf(__Leaf const&) = delete;
    __Leaf& operator=(__Leaf const&) = delete;

    __Leaf* top;
    __Leaf* l;
    __Leaf* r;
    int len;

    inline __Leaf() : top(0), l(0), r(0), len(0) {}
    virtual ~__Leaf() {}

    __Leaf* next() const;
    __Leaf* prev() const;

protected:
    // internal copy helpers (unused once copying deleted, but kept for symmetry)
    inline __Leaf(__Leaf const& o) : top(o.top), l(o.l), r(o.r), len(o.len) {}
    inline __Leaf const& operator=(__Leaf const& o) {
        top = o.top; l = o.l; r = o.r; len = o.len; return *this;
    }
};

// -----------------------------------------------------------------------------
// Tree iterator (internal base)
// -----------------------------------------------------------------------------
class __TIter {
    friend class __Tree;

protected:
    __Leaf* n;

    inline __TIter(__TIter const& o) : n(o.n) {}
    inline __TIter(__Leaf* n_) : n(n_) {}
    inline __TIter& operator=(__TIter const& o) { n = o.n; return *this; }
    inline __TIter& operator++() { if (n) n = n->next(); return *this; }
    inline __TIter& operator--() { if (n) n = n->prev(); return *this; }
};

// -----------------------------------------------------------------------------
// Pooled tree base
// -----------------------------------------------------------------------------
class __Tree {
public:
    __Tree(__Tree const&) = delete;
    __Tree& operator=(__Tree const&) = delete;

protected:
    friend class __TIter;

    __Leaf* root;
    unsigned long count;
    __mem_pool* mp;

    __Tree(__mem_pool* mp_);
    virtual ~__Tree();

    __Leaf* __begin() const;
    __Leaf* __rend() const;

    __Leaf* __remove(__Leaf*);      // unlink without destroy/free
    void __fixAdd(__Leaf*);         // re-balance after add
    void __fixRemove(__Leaf *i);    // re-balance after remove

    // rotations
    void drr(__Leaf *i, __Leaf *j);
    void drl(__Leaf *i, __Leaf *j);
    void rr(__Leaf *i, __Leaf *j);
    void rl(__Leaf *i, __Leaf *j);

    static __TIter const nend;

public:
    inline unsigned long size() const { return count; }
};

// -----------------------------------------------------------------------------
// Set<T, L> public API
// -----------------------------------------------------------------------------
template<class T, class L = less<T> >
class set : public __Tree {
protected:
    struct Leaf : public __Leaf {
        Leaf(Leaf const&) = delete;
        Leaf& operator=(Leaf const&) = delete;

        T t;
        inline Leaf(T const& _t) : __Leaf(), t(_t) {}

        inline Leaf* next() const { return (Leaf*) __Leaf::next(); }
        inline Leaf* prev() const { return (Leaf*) __Leaf::prev(); }
        inline T& operator*() { return t; }
        inline operator T&() { return t; }
        inline T const& operator*() const { return t; }
        inline operator T const&() const { return t; }
    };

    __Leaf* __insert_loop(T const&, int &roti, long &limit, __Leaf **rotator); // declared, not used here
    int __erase_search(T const &t); // declared, not used here

    inline Leaf* __create_node(T const &t) {
        // pooled allocation + placement new
        void* mem = mp->alloc();
        if (!mem) return 0;
        return new (mem) Leaf(t);
    }

public:
    // traits
    typedef T value_type;
    typedef T & reference;
    typedef T const & const_reference;
    typedef T * pointer;
    typedef T const * const_pointer;

    typedef signed int difference_type;
    typedef unsigned int size_type;

    // iterators
    class iterator : protected __TIter {
    public:
        inline iterator() : __TIter(0) {}
        inline iterator(Leaf* l) : __TIter(l) {}
        inline iterator(iterator const& it) : __TIter(it.n) {}

        inline iterator& operator++() { return (iterator&)__TIter::operator++(); }
        inline iterator& operator--() { return (iterator&)__TIter::operator--(); }
        inline iterator operator++(int) { iterator x(*this); operator++(); return x; }
        inline iterator operator--(int) { iterator x(*this); operator--(); return x; }
        inline int operator!=(iterator const& o) const { return n != o.n; }
        inline int operator!=(int) const { return n != 0; }
        inline int operator!() const { return n == 0; }      // fixed
        inline int operator==(int) const { return n == 0; }
        inline operator T&() { return (T&)*(Leaf*)n; }
        inline T& operator*() { return (T&)*(Leaf*)n; }
        inline T* operator->() { return &((Leaf*)n)->t; }
        inline operator T const&() const { return (T const&)*(Leaf*)n; }
        inline T const& operator*() const { return (T const&)*(Leaf*)n; }
    };

    class const_iterator : protected __TIter {
    public:
        inline const_iterator() : __TIter(0) {}
        inline const_iterator(const_iterator const& it) : __TIter(it.n) {}
        inline const_iterator(Leaf* l) : __TIter(l) {}

        inline const_iterator& operator++() { return (const_iterator&)__TIter::operator++(); }
        inline const_iterator& operator--() { return (const_iterator&)__TIter::operator--(); }
        inline const_iterator operator++(int) { const_iterator x(*this); operator++(); return x; }
        inline const_iterator operator--(int) { const_iterator x(*this); operator--(); return x; }
        inline int operator!=(const_iterator const& o) const { return n != o.n; }
        inline int operator!() const { return n == 0; }      // fixed
        inline int operator==(int) const { return n == 0; }
        inline operator T const&() const { return (T const&)*(Leaf*)n; }
        inline T const& operator*() const { return (T const&)*(Leaf*)n; }
    };

    inline set() : __Tree(new __mem_pool(sizeof(Leaf))) {}

    inline iterator begin() { return (Leaf*)__Tree::__begin(); }
    inline iterator end() { return (iterator&) nend; }
    inline iterator rbegin() { return (Leaf*)__Tree::__rend(); }
    inline iterator rend() { return (iterator&) nend; }

    inline const_iterator begin() const { return const_iterator((Leaf*)__Tree::__begin()); }  // fixed
    inline const_iterator end() const { return const_iterator((Leaf*)0); }                    // fixed
    inline const_iterator rbegin() const { return const_iterator((Leaf*)__Tree::__rend()); }  // fixed
    inline const_iterator rend() const { return const_iterator((Leaf*)0); }                   // fixed

    inline iterator insert(T const &t) { return __insert(t); }
    inline iterator find(T const &t) const { return __find(t); }

    int erase(const T &t);
    void clear();

protected:
    Leaf* __insert(T const &t);
    Leaf* __find(T const &t) const;
};

// -----------------------------------------------------------------------------
// Pooled erase/clear using explicit destructor + mp->free
// -----------------------------------------------------------------------------
template<class T, class L>
int set<T, L>::erase(T const &t) {
    Leaf* i = __find(t);
    if (!i) return 0;
    __remove(i);      // unlink from tree, fix balance
    i->~Leaf();       // destroy payload
    mp->free(i);      // free memory to pool
    --count;
    return 1;
}

template<class T, class L>
void set<T, L>::clear() {
    for (;;) {
        Leaf* i = (Leaf*)__begin();
        if (!i) break;
        __remove(i);
        i->~Leaf();
        mp->free(i);
        --count;
    }
}

// -----------------------------------------------------------------------------
// Insert with pooled allocation; rebalance via __fixAdd
// -----------------------------------------------------------------------------
template<class T, class L>
typename set<T, L>::Leaf* set<T, L>::__insert(T const &t) {
    if (root == 0) {
        Leaf* neu = __create_node(t);
        if (!neu) return 0;
        root = neu;
        root->top = 0;
        ++count;
        return neu;
    }

    L less;
    Leaf *i = (Leaf*)root;
    for (;;) {
        if (less(t, **i)) {
            if (i->l == 0) {
                Leaf* neu = __create_node(t);
                if (!neu) return 0;
                i->l = neu;
                neu->top = i;
                ++count;
                __fixAdd(neu);
                return neu;
            }
            i = (Leaf*)i->l;
        } else if (less(**i, t)) {
            if (i->r == 0) {
                Leaf* neu = __create_node(t);
                if (!neu) return 0;
                i->r = neu;
                neu->top = i;
                ++count;
                __fixAdd(neu);
                return neu;
            }
            i = (Leaf*)i->r;
        } else {
            // equal key: replace value semantics (non-unique set)
            // create a scratch copy and return it (as original design)
            Leaf* neu = __create_node(i->t);
            if (!neu) return 0;
            i->t = t;
            return neu;
        }
    }
}

// -----------------------------------------------------------------------------
// Find
// -----------------------------------------------------------------------------
template<class T, class L>
typename set<T, L>::Leaf* set<T, L>::__find(T const &t) const {
    L less;
    for (Leaf* p = (Leaf*)root; p != 0;) {
        if (less(t, **p)) {
            p = (Leaf*)p->l;
        } else if (less(**p, t)) {
            p = (Leaf*)p->r;
        } else {
            return p;
        }
    }
    return 0;
}

} // namespace mstl

#endif // __MINISTL__SET_H__
