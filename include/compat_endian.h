#ifndef BEBBOSSH_COMPAT_ENDIAN_H
#define BEBBOSSH_COMPAT_ENDIAN_H

#if defined(__has_include)
#  if __has_include(<endian.h>)
#    include <endian.h>
#  elif __has_include(<sys/endian.h>)
#    include <sys/endian.h>
#  elif __has_include(<machine/endian.h>)
#    include <machine/endian.h>
#  endif
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

#ifndef BYTE_ORDER
#  if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#    define BYTE_ORDER BIG_ENDIAN
#  elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#    define BYTE_ORDER LITTLE_ENDIAN
#  elif defined(__BIG_ENDIAN__)
#    define BYTE_ORDER BIG_ENDIAN
#  else
#    define BYTE_ORDER LITTLE_ENDIAN
#  endif
#endif

#endif
