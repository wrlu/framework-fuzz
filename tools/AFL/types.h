/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


/*
   american fuzzy lop - type definitions and minor macros
   ------------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>
*/

#ifndef _HAVE_TYPES_H
#define _HAVE_TYPES_H

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

/*

   Ugh. There is an unintended compiler / glibc #include glitch caused by
   combining the u64 type an %llu in format strings, necessitating a workaround.

   In essence, the compiler is always looking for 'unsigned long long' for %llu.
   On 32-bit systems, the u64 type (aliased to uint64_t) is expanded to
   'unsigned long long' in <bits/types.h>, so everything checks out.

   But on 64-bit systems, it is #ifdef'ed in the same file as 'unsigned long'.
   Now, it only happens in circumstances where the type happens to have the
   expected bit width, *but* the compiler does not know that... and complains
   about 'unsigned long' being unsafe to pass to %llu.

 */

#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#ifndef MIN
#  define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#  define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

#define SWAP16(_x) ({ \
    u16 _ret = (_x); \
    (u16)((_ret << 8) | (_ret >> 8)); \
  })

#define SWAP32(_x) ({ \
    u32 _ret = (_x); \
    (u32)((_ret << 24) | (_ret >> 24) | \
          ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00)); \
  })

#ifdef AFL_LLVM_PASS
#  define AFL_R(x) (random() % (x))
#else
#  define R(x) (random() % (x))
#endif /* ^AFL_LLVM_PASS */

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY_AFL(x) STRINGIFY_INTERNAL(x)

#define MEM_BARRIER() \
  __asm__ volatile("" ::: "memory")

#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

#endif /* ! _HAVE_TYPES_H */
