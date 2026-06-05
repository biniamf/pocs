## CVE-2026-8258: Stack buffer overflow in validate_format due to off-by-one length check

validate_format() (sqstdlib/sqstdstring.cpp) copies a format specifier into a
20-byte stack buffer using memcpy, but the preceding length check uses >
instead of >=, allowing a specifier of exactly MAX_FORMAT_LEN (20) characters
to pass.  The memcpy then writes 21 bytes into &fmt[1] (the buffer starts at
fmt[0] and is 20 bytes), overflowing by 1-3 bytes past the stack buffer.

- Version: Squirrel 3.2 stable
- Commit:  f9267f2


### Root cause (sqstdstring.cpp):
```c
#define MAX_FORMAT_LEN 20

SQInteger validate_format(HSQUIRRELVM v, SQChar *fmt, const SQChar *src, ...)
{
    SQChar stype;
    SQInteger n = 0, start = ...;
    ...
    // loop advances n past flags, width, precision
    ...
    if (n-start > MAX_FORMAT_LEN)                    // OFF-BY-ONE: > should be >=
        return sq_throwerror(v,_SC("format too long"));

    memcpy(&fmt[1],&src[start],((n-start)+1)*sizeof(SQChar));  // writes n-start+1 bytes
    fmt[(n-start)+2] = '\0';                                   // NUL terminator
```

### Proof-of-concept:

  Squirrel script: [poc_format_stack_bof.nut](https://github.com/biniamf/pocs/tree/main/squirrel-validate_format-memcpy-oob)

  ./bin/sq_static poc_format_stack_bof.nut


#### ASan output:

```c
=================================================================
==157540==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xe6084cf08cd4 at pc 0xea0850347d80 bp 0xffffd4ff8030 sp 0xffffd4ff7810
WRITE of size 21 at 0xe6084cf08cd4 thread T0
    #0 0xea0850347d7c in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0xea08501ee2b8 in memcpy /usr/include/aarch64-linux-gnu/bits/string_fortified.h:29
    #2 0xea08501ee2b8 in validate_format /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdstring.cpp:65
    #3 0xea08501eed84 in sqstd_format /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdstring.cpp:99
    #4 0xea08501efbb0 in _string_format /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdstring.cpp:195
    #5 0xea084fee1cf8 in SQVM::CallNative(SQNativeClosure*, long long, long long, SQObjectPtr&, int, bool&, bool&) /home/roo/Desktop/squirrel/squirrel/squirrel/sqvm.cpp:1219
    #6 0xea084fee55e8 in SQVM::Execute(SQObjectPtr&, long long, long long, SQObjectPtr&, unsigned long long, SQVM::ExecutionType) /home/roo/Desktop/squirrel/squirrel/squirrel/sqvm.cpp:781
    #7 0xea084fefbfcc in SQVM::Call(SQObjectPtr&, long long, long long, SQObjectPtr&, unsigned long long) /home/roo/Desktop/squirrel/squirrel/squirrel/sqvm.cpp:1610
    #8 0xea084fe3c2bc in sq_call /home/roo/Desktop/squirrel/squirrel/squirrel/sqapi.cpp:1178
    #9 0xb1b2d373600c in Interactive /home/roo/Desktop/squirrel/squirrel/sq/sq.c:288
    #10 0xb1b2d37362bc in main /home/roo/Desktop/squirrel/squirrel/sq/sq.c:333
    #11 0xea084f3d2598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #12 0xea084f3d2678 in __libc_start_main_impl ../csu/libc-start.c:360
    #13 0xb1b2d37342ec in _start (/home/roo/Desktop/squirrel/squirrel/build/bin/sq+0x42ec) (BuildId: 243fa92ffb6d6fb8e0d0a0bf64ed057a731301d6)

Address 0xe6084cf08cd4 is located in stack of thread T0 at offset 212 in frame
    #0 0xea08501ee878 in sqstd_format /home/roo/Desktop/squirrel/squirrel/sqstdlib/sqstdstring.cpp:71

  This frame has 6 object(s):
    [48, 52) 'tf' (line 105)
    [64, 72) 'format' (line 72)
    [96, 104) 'w' (line 82)
    [128, 136) 'ts' (line 103)
    [160, 168) 'ti' (line 104)
    [192, 212) 'fmt' (line 74) <== Memory access at offset 212 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /usr/include/aarch64-linux-gnu/bits/string_fortified.h:29 in memcpy
Shadow bytes around the buggy address:
  0xe6084cf08a00: f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5
  0xe6084cf08a80: f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5
  0xe6084cf08b00: f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5
  0xe6084cf08b80: f5 f5 f5 f5 f5 f5 f5 f5 00 00 00 00 00 00 00 00
  0xe6084cf08c00: f1 f1 f1 f1 f1 f1 04 f2 00 f2 f2 f2 00 f2 f2 f2
=>0xe6084cf08c80: 00 f2 f2 f2 00 f2 f2 f2 00 00[04]f3 f3 f3 f3 f3
  0xe6084cf08d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe6084cf08d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe6084cf08e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe6084cf08e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe6084cf08f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==157540==ABORTING
```

### Impact:

  - Immediate:  DoS.
  - Potential:  Stack buffer overflow.  The 3-byte overwrite can corrupt
                adjacent stack variables or the saved frame pointer.
  - Scope:      Any application running untrusted Squirrel scripts that have
                access to the string library.
  ```
