## CVE-2026-9541: Heap buffer overflow in ReadObject via negative string length in crafted bytecode

ReadObject() (squirrel/sqobject.cpp) reads a string length from the bytecode
stream as signed SQInteger and passes it to GetScratchPad() and SafeRead()
without rejecting negative values.  A crafted .cnut bytecode file with a
negative OT_STRING length bypasses the scratchpad resize (GetScratchPad only
resizes when size > 0) and causes SafeRead to pass the negative length to
fread, which interprets it as a very large unsigned size_t, writing past the
existing scratchpad buffer.

The vulnerability is reachable from sq_static (or any embedder calling
sqstd_loadfile / sq_readclosure) by loading a crafted .cnut bytecode file.

- Version: Squirrel 3.2 stable
- Commit:  f9267f2


Root cause (sqobject.cpp:342-355):
  ```c
    case OT_STRING:
        SafeRead(v,read,up,&len,sizeof(SQInteger));         // len from untrusted stream
        dest = _ss(v)->GetScratchPad(sq_rsl(len));           // no negative check
        SafeRead(v,read,up,dest,sq_rsl(len));                // OOB write when len < 0
  ```
  GetScratchPad (sqstate.cpp:374-393) only reallocates when size > 0:
```c
    SQChar *GetScratchPad(SQInteger size)
    {
        ...
        if(size>0) {
            if(_scratchpadsize < size) {
                _scratchpadsize = size;
                _scratchpad=(SQChar *)SQ_REALLOC(...);
            }
            return _scratchpad;
        }
        return NULL;
    }
```
  When len is negative, sq_rsl(len) is still negative (sq_rsl is
  len*sizeof(SQChar) = len*1 on non-Unicode).  GetScratchPad returns
  the existing buffer (size <= 0, no resize).  SafeRead then passes
  the negative value to fread, which interprets it as a huge unsigned
  size_t, writing all remaining file data into the small scratchpad
  buffer leading to heap buffer overflow.


## Proof-of-Concept
  
Crafted cnut file: [poc_heap_oob_readobject.cnut](https://github.com/biniamf/pocs/tree/main/squirrel-sqobject-readobject-neg-len-oob)

```bash
  sq_static poc_heap_oob_readobject.cnut
```

ASan output:

```bash
=================================================================
==162238==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xe553a91e04c6 at pc 0xe843aac5f4cc bp 0xffffd020f070 sp 0xffffd020e850
WRITE of size 256 at 0xe553a91e04c6 thread T0
    #0 0xe843aac5f4c8 in fread ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1030
    #1 0xaad1c47d8260 in fread /usr/include/aarch64-linux-gnu/bits/stdio2.h:331
    #2 0xaad1c47d8260 in sqstd_fread /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdio.cpp:21
    #3 0xaad1c47d82c0 in file_read(void*, void*, long long) /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdio.cpp:331
    #4 0xaad1c4768d8c in SafeRead(SQVM*, long long (*)(void*, void*, long long), void*, void*, long long) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:296
    #5 0xaad1c47699f0 in ReadObject(SQVM*, void*, long long (*)(void*, void*, long long), SQObjectPtr&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:351
    #6 0xaad1c476b968 in SQFunctionProto::Load(SQVM*, void*, long long (*)(void*, void*, long long), SQObjectPtr&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:485
    #7 0xaad1c476ccdc in SQClosure::Load(SQVM*, void*, long long (*)(void*, void*, long long), SQObjectPtr&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqobject.cpp:395
    #8 0xaad1c46ffc64 in sq_readclosure /home/roo/Desktop/squirrel/squirrel/squirrel/sqapi.cpp:1284
    #9 0xaad1c47d9994 in sqstd_loadfile /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdio.cpp:356
    #10 0xaad1c46ee7f0 in getargs /home/roo/Desktop/squirrel/squirrel/sq/sq.c:175
    #11 0xaad1c46ef830 in main /home/roo/Desktop/squirrel/squirrel/sq/sq.c:330
    #12 0xe843a9fe2598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #13 0xe843a9fe2678 in __libc_start_main_impl ../csu/libc-start.c:360
    #14 0xaad1c46ed8ec in _start (/home/roo/Desktop/squirrel/squirrel/build/bin/sq_static+0x22d8ec) (BuildId: 77438f9a7bb01fa2bb5242d5f1987561c719aa3f)

0xe553a91e04c6 is located 0 bytes after 198-byte region [0xe553a91e0400,0xe553a91e04c6)
allocated by thread T0 here:
    #0 0xe843aacd93dc in realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:81
    #1 0xaad1c4763ddc in sq_vm_realloc(void*, unsigned long long, unsigned long long) /home/roo/Desktop/squirrel/squirrel/squirrel/sqmem.cpp:8
    #2 0xaad1c4778488 in SQSharedState::GetScratchPad(long long) /home/roo/Desktop/squirrel/squirrel/squirrel/sqstate.cpp:381
    #3 0xaad1c4743a50 in SQVM::Raise_Error(char const*, ...) /home/roo/Desktop/squirrel/squirrel/squirrel/sqdebug.cpp:64
    #4 0xaad1c4744418 in SQVM::Raise_IdxError(SQObjectPtr const&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqdebug.cpp:94
    #5 0xaad1c47b2b90 in SQVM::Get(SQObjectPtr const&, SQObjectPtr const&, SQObjectPtr&, unsigned long long, long long) /home/roo/Desktop/squirrel/squirrel/squirrel/sqvm.cpp:1318
    #6 0xaad1c46f74f0 in sq_get /home/roo/Desktop/squirrel/squirrel/squirrel/sqapi.cpp:1042
    #7 0xaad1c47e0c78 in init_streamclass(SQVM*) /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdstream.cpp:259
    #8 0xaad1c47e1200 in declare_stream(SQVM*, char const*, void*, char const*, tagSQRegFunction const*, tagSQRegFunction const*) /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdstream.cpp:292
    #9 0xaad1c47d62a0 in sqstd_register_bloblib /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdblob.cpp:281
    #10 0xaad1c46ef7f4 in main /home/roo/Desktop/squirrel/squirrel/sq/sq.c:319
    #11 0xe843a9fe2598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #12 0xe843a9fe2678 in __libc_start_main_impl ../csu/libc-start.c:360
    #13 0xaad1c46ed8ec in _start (/home/roo/Desktop/squirrel/squirrel/build/bin/sq_static+0x22d8ec) (BuildId: 77438f9a7bb01fa2bb5242d5f1987561c719aa3f)

SUMMARY: AddressSanitizer: heap-buffer-overflow /usr/include/aarch64-linux-gnu/bits/stdio2.h:331 in fread
Shadow bytes around the buggy address:
  0xe553a91e0200: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0xe553a91e0280: fa fa fa fa fa fa fa fa fd fd fd fd fd fd fd fd
  0xe553a91e0300: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0xe553a91e0380: fd fd fd fd fd fd fd fd fa fa fa fa fa fa fa fa
  0xe553a91e0400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0xe553a91e0480: 00 00 00 00 00 00 00 00[06]fa fa fa fa fa fa fa
  0xe553a91e0500: fa fa fa fa fa fa fa fa fd fd fd fd fd fd fd fd
  0xe553a91e0580: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0xe553a91e0600: fd fd fd fd fd fd fd fd fa fa fa fa fa fa fa fa
  0xe553a91e0680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe553a91e0700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==162238==ABORTING
```

Impact:

  - Immediate:  DoS
  - Potential:  Heap buffer overflow with attacker-controlled overflow content
                (subsequent file bytes).  Exploitable for arbitrary code
                execution in applications loading untrusted .cnut files.
  - Scope:      Any application using sqstd_loadfile or sq_readclosure to load
                bytecode from untrusted sources.
