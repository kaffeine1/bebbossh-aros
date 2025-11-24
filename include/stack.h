/*
 *      Author: Stefan "Bebbo"Franke
 */
#ifndef __STACK_H__
#define __STACK_H__

/**
 * Simple container to manage max n items.
 * Good enough for small n - no need for a hash table.
 * The access uses an index
 * - the channel number
 * - the socket
 */

class __Index {
	void ** data;
	uint32_t max;
	uint32_t count;
public:
	__Index(uint32_t max_);
	~__Index();

	inline uint32_t getMax() const { return max; }
	inline uint32_t getCount() const { return count; }

	uint32_t getFreeIndex() const;

protected:
	void * remove(uint32_t const index);
	void * replace(uint32_t const index, void * t);
	uint32_t add(uint32_t const index, void * t);
	void * operator[](uint32_t const index) const;
};

/**
 * Use the __Index as typed index or as a stack.
 */
template <class T> class Stack : public __Index {
public:
	inline Stack<T>(uint32_t max = 0) : __Index(max) {}
	inline ~Stack<T>() {}

	inline T * remove(uint32_t const index) { return (T*)__Index::remove(index); }
	inline uint32_t add(uint32_t const index, T * t) { return __Index::add(index, t); }
	inline T * replace(uint32_t const index, T * t) { return (T*)__Index::replace(index, t);}
	inline T * operator[](uint32_t const index) const { return (T*)__Index::operator[](index);}

	inline void push(T * t) { add(getCount(), t); }
	inline T * pop() { return getCount() > 0 ? remove(getCount() - 1) : 0; }
	inline T * peek() const { return getCount() > 0 ? (*this)[getCount() - 1] : 0; }
};

class ClientChannel;

class WithSocket {
protected:
	int sockFd;
	bool open;
public:
	inline WithSocket() : sockFd(-1), open(false) {}
	virtual ~WithSocket();

	void __close();

	inline int getSockFd() const { return sockFd; }
	inline void setSockFd(int sfd) { sockFd = sfd; open = true; }
	inline bool isOpen() const { return open; }
};

class Listener : public WithSocket {
public:
	inline Listener() {}
	virtual ~Listener() {}

	virtual bool isBufferFree() const = 0;
	virtual int processSocketData(void * data, int len) = 0;
	virtual void close() = 0;
	virtual void noop() {};
	virtual ClientChannel * getChannel() {
		return 0;
	}
};

struct Acceptor : public WithSocket {
public:
	inline Acceptor() {}
	virtual ~Acceptor() {}

	virtual bool init() = 0;
	virtual bool handleAccept(int sockfd) = 0;
};

#endif //__STACK_H__
