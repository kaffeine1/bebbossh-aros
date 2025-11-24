/*
 * ministl list
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
 * Purpose: Provide a lightweight doubly-linked list container for the
 *          ministl subset used in ministl.
 *
 * Features:
 *  - Doubly-linked list with push_front/back and pop_front/back
 *  - Iterators and const_iterators for traversal
 *  - Node linking/unlinking helpers
 *
 * Notes:
 *  - Copying is disabled for internal node/iterator/list types using = delete
 *  - Uses __mem_pool for node allocation/free
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MINISTL__LIST_H_
#define __MINISTL__LIST_H_

#ifndef MINISTL__COMMON_H
#include <ministl/common.h>
#endif

#ifndef __ALLOC_H__
#include <ministl/alloc.h>
#endif

namespace mstl {

  //==============================================================================
  class __Node {
  public:
    __Node(__Node const&) = delete;
    __Node& operator=(__Node const&) = delete;

  protected:
    __Node * p;
    __Node * n;

    __Node() : p(0), n(0) {}

  public:
    __Node * prev() const { return p; }
    __Node * next() const { return n; }

    void addBefore(__Node * o) {
      o->p = p;
      if (p) p->n = o;
      p = o;
      o->n = this;
    }
    void addBehind(__Node * o) {
      o->n = n;
      if (n) n->p = o;
      n = o;
      o->p = this;
    }
    __Node * unlink() {
      if (p) p->n = n;
      if (n) n->p = p;
      return this;
    }
  };

  //==============================================================================
  class __LIter {
  public:
    __LIter(__LIter const&) = delete;
    __LIter& operator=(__LIter const&) = delete;

    friend class __List;

  protected:
    __Node * n;
    inline __LIter(__Node * n_) : n(n_) {}
    inline __LIter & operator ++() { if (n) n = n->next(); return *this; }
    inline __LIter & operator --() { if (n) n = n->prev(); return *this; }
  };

  //==============================================================================
  class __List {
  public:
    __List(__List const&) = delete;
    __List& operator=(__List const&) = delete;

    friend class __LIter;

  protected:
    __Node * head;
    __Node * tail;
    unsigned int count;
    __mem_pool * mp;

    __List(__mem_pool * mp_) : head(0), tail(0), count(0), mp(mp_) {}
    virtual ~__List() {}
    inline __Node * __node(__LIter  const * i) { return i->n; }
  };

  //==============================================================================
  template<class T>
  class list: public __List {
  public:
    class Node: public __Node {
    public:
      Node(Node const&) = delete;
      Node& operator=(Node const&) = delete;

      T t;
      inline Node(T const & _t) : t(_t) {}

      inline Node * next() const { return (Node *) __Node::next(); }
      inline Node * prev() const { return (Node*) __Node::prev(); }
      inline T & operator *() { return t; }
      inline operator T &() { return t; }
      inline T const & operator *() const { return t; }
      inline operator T const &() const { return t; }
    };

  public:
    typedef T value_type;
    typedef T & reference;
    typedef T const & const_reference;
    typedef T * pointer;
    typedef T const * const_pointer;

    typedef signed int difference_type;
    typedef unsigned int size_type;

    class iterator: public __LIter {
    public:
      iterator() : __LIter(0) {}
      iterator(Node * l) : __LIter(l) {}
      iterator(iterator const & it) : __LIter(it.n) {}

      inline iterator & operator ++() { return (iterator&) __LIter::operator ++(); }
      inline iterator & operator --() { return (iterator&) __LIter::operator --(); }
      inline iterator operator ++(int) { iterator x(*this); operator ++(); return x; }
      inline iterator operator --(int) { iterator x(*this); operator --(); return x; }
      inline int operator !=(iterator const & o) const { return n != o.n; }
      inline int operator !=(int) const { return n != 0; }
      inline int operator !() const { return n == 0; }
      inline int operator ==(int) const { return n == 0; }
      inline operator T &() { return (T&) *(Node*) n; }
      inline T & operator *() { return (T&) *(Node*) n; }
      inline T * operator ->() { return &((Node*) n)->t; }
      inline operator T const &() const { return (T const &) *(Node*) n; }
      inline T const & operator *() const { return (T const &) *(Node*) n; }
    };

    class const_iterator: protected __LIter {
    public:
      const_iterator() : __LIter(0) {}
      const_iterator(const_iterator const & it) : __LIter(it.n) {}
      const_iterator(Node * l) : __LIter(l) {}

      inline const_iterator & operator ++() { return (const_iterator&) __LIter::operator ++(); }
      inline const_iterator & operator --() { return (const_iterator&) __LIter::operator --(); }
      inline const_iterator operator ++(int) { const_iterator x(*this); operator ++(); return x; }
      inline const_iterator operator --(int) { const_iterator x(*this); operator --(); return x; }
      inline int operator !=(const_iterator const & o) const { return n != o.n; }
      inline int operator !=(int) const { return n != 0; }
      inline int operator !() const { return n == 0; }
      inline int operator ==(int) const { return n == 0; }
      inline operator T const &() const { return (T const &) *(Node*) n; }
      inline T const & operator *() const { return (T const &) *(Node*) n; }
    };

    inline list() : __List(new __mem_pool(sizeof(Node))) {}

    inline ~list() {
      while (head) {
        Node * n = (Node*)head->unlink();
        head = n->next();
        n->~Node();
        mp->free(n);
      }
      delete mp;
    }

    inline unsigned int size() const { return count; }

    inline iterator begin() { return (Node*)head; }
    inline iterator end() { return 0; }
    inline iterator rbegin() { return (Node*)tail; }
    inline iterator rend() { return 0; }

    inline const_iterator begin() const { return const_iterator((Node*)head); }
    inline const_iterator end() const { return const_iterator(0); }
    inline const_iterator rbegin() const { return const_iterator((Node*)tail); }
    inline const_iterator rend() const { return const_iterator(0); }

    // Front Insertion Sequence
    inline void push_front(const T& t) {
      Node* n = (Node*)mp->alloc();
      if (!n) return;
      new (n) Node(t);
      ++count;
      if (head) { head->addBefore(n); head = n; }
      else head = tail = n;
    }

    // Back Insertion Sequence
    void push_back(const T& t) {
      Node* n = (Node*)mp->alloc();
      if (!n) return;
      new (n) Node(t);
      ++count;
      if (tail) { tail->addBehind(n); tail = n; }
      else head = tail = n;
    }

    // Front Removal
    void pop_front() {
      if (!head) return;
      --count;
      Node * r = (Node*)head->unlink();
      head = r->next();
      if (!head) tail = 0;
      r->~Node();
      mp->free(r);
    }

    // Back Removal
    void pop_back() {
      if (!tail) return;
      --count;
      Node * r = (Node*)tail->unlink();
      tail = r->prev();
      if (!tail) head = 0;
      r->~Node();
      mp->free(r);
    }

    // Remove first matching element
    inline void remove(T const & a) {
      for (iterator i = begin(); i != end(); ++i) {
        T const & b = *i;
        if (b == a) {
          Node * n = (Node *)__node(&i)->unlink();
          if (!n->prev()) head = n->next();
          if (!n->next()) tail = n->prev();
          --count;
          n->~Node();
          mp->free(n);
          break;
        }
      }
    }
  };

} // namespace mstl

#endif /* __MINISTL__LIST_H_ */
