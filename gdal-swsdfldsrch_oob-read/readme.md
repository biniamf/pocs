## Out-of-bounds read in GDAL's vendored HDF-EOS library via size_t underflow in SWSDfldsrch

SWSDfldsrch (frmts/hdf4/hdf-eos/SWapi.c) strips quotes from a metadata-derived
string using memmove(name, name+1, strlen(name)-2) and name[strlen(name)-2]=0
without checking that strlen(name) >= 2.  When the FieldList metadata value is
empty (strlen=0), the expression strlen(name)-2 wraps to SIZE_MAX-1
(18446744073709551614) due to unsigned underflow, causing memmove to attempt a
read of ~18 exabytes from the stack — immediate crash.

- Version: GDAL 3.13.0dev-4c681ad376
- Commit:  4c681ad376


Root cause (SWapi.c:3081-3083):
```c
    EHgetmetavalue(metaptrs, "FieldList", name);  /* return status ignored */
    memmove(name, name + 1, strlen(name) - 2);    // <- SIZE_MAX-1 if name=""
    name[strlen(name) - 2] = 0;                   // <- same underflow
```
  strlen() returns size_t (unsigned).  0 - 2 = 0xFFFFFFFFFFFFFFFE on 64-bit.
  name is char name[2048] on the stack.  The memmove reads SIZE_MAX-1 bytes
  starting at name+1, writing to name — catastrophic stack-buffer-overflow.


### PoC
The vulnerability is reachable from gdalmdiminfo via a crafted HDF-EOS swath file: [poc_swsdfldsrch_oob-read.he4]()

```bash
  ASAN_OPTIONS=detect_leaks=0 ./gdalmdiminfo poc_swsdfldsrch_oob-read.he4
```

ASan output:
```bash
=================================================================
==17804==ERROR: AddressSanitizer: unknown-crash on address 0xf40c8ff0e301 at pc 0xf80c99d6d448 bp 0xffffec2e7420 sp 0xffffec2e7410
READ of size 18446744073709551614 at 0xf40c8ff0e301 thread T0
    #0 0xf80c99d6d444 in memmove /usr/include/aarch64-linux-gnu/bits/string_fortified.h:36
    #1 0xf80c99d6d444 in SWSDfldsrch /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/SWapi.c:3082
    #2 0xf80c99d71f0c in SWfinfo /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/SWapi.c:1402
    #3 0xf80c99d740f0 in SWfieldinfo /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/SWapi.c:1479
    #4 0xf80c99e048fc in HDF4SwathSubGroup::OpenMDArray(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, char const* const*) const /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf4multidim.cpp:1414
    #5 0xf80c9ae3b2a0 in DumpArrays /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1062
    #6 0xf80c9ae3b2a0 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1151
    #7 0xf80c9ae39db4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #8 0xf80c9ae39db4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #9 0xf80c9ae39db4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #10 0xf80c9ae3d28c in GDALMultiDimInfo /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1360
    #11 0xb33bcd1beb3c in main /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_bin.cpp:83
    #12 0xf80c93ec2598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #13 0xf80c93ec2678 in __libc_start_main_impl ../csu/libc-start.c:360
    #14 0xb33bcd1bf0ec in _start (/home/roo/Desktop/gdal/build/apps/gdalmdiminfo+0x6f0ec) (BuildId: bf1bbb6a7dc6ab35d8312ba39c07c6f3cde7f417)

Address 0xf40c8ff0e301 is located in stack of thread T0 at offset 769 in frame
    #0 0xf80c99d6c72c in SWSDfldsrch /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/SWapi.c:2986

  This frame has 5 object(s):
    [32, 36) 'dum' (line 2992)
    [48, 64) 'metaptrs' (line 3000)
    [80, 592) 'dums' (line 2993)
    [656, 736) 'swathname' (line 2997)
    [768, 2816) 'name' (line 2996) <== Memory access at offset 769 is inside this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: unknown-crash /usr/include/aarch64-linux-gnu/bits/string_fortified.h:36 in memmove
Shadow bytes around the buggy address:
  0xf40c8ff0e080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf40c8ff0e100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf40c8ff0e180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf40c8ff0e200: 00 00 00 00 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2
  0xf40c8ff0e280: f2 f2 00 00 00 00 00 00 00 00 00 00 f2 f2 f2 f2
=>0xf40c8ff0e300:[00]00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf40c8ff0e380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf40c8ff0e400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf40c8ff0e480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf40c8ff0e500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf40c8ff0e580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==17804==ABORTING
```

### Impact:
  - Immediate:  DoS
