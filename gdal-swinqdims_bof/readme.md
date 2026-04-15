## Heap buffer overflow in GDAL's vendored HDF-EOS library via unbounded strcat in SWinqdims

SWinqdims (frmts/hdf4/hdf-eos/SWapi.c) appends dimension names into a caller-
provided buffer using repeated strcat without bounds checking. The caller in
HDF4SwathGroup::GetDimensions (hdf4multidim.cpp:1476) sizes the buffer with
SWnentries(), which subtracts 2 bytes per entry under the assumption that every
DimensionName value in the HDF-EOS metadata is double-quoted. When a crafted
HDF-EOS file supplies unquoted DimensionName values (which pass all HDF library
validation), SWnentries undercounts the required buffer by 2 bytes per dimension
entry while SWinqdims writes the full name length — producing a heap buffer
overflow of 2*N bytes for N dimension entries.

- Version: GDAL 3.13.0dev-4c681ad376
- Commit:  4c681ad376

### Root cause:

SWnentries (SWapi.c):
```c
    EHgetmetavalue(metaptrs, "DimensionName", utlstr);
    *strbufsize += (int32)strlen(utlstr) - 2;   // <- assumes value is quoted
```
The subtraction of 2 intends to strip the surrounding double quotes ("name").
When DimensionName=value (no quotes), strlen(utlstr)=L and strbufsize grows by
L-2 instead of L.

SWinqdims (SWapi.c):
```c
    EHgetmetavalue(metaptrs, "DimensionName", utlstr);  // utlstr = value (no quotes)
    REMQUOTE(utlstr);   // no-op: first char is not '"', does nothing
    if (nDim > 0)
        strcat(dimnames, ",");
    strcat(dimnames, utlstr);   // <- writes L bytes, but only L-2 were accounted for
```
Caller (hdf4multidim.cpp):
```c
    dimNames.resize(nStrBufSize);   // allocates SWnentries result (undercounted)
    SWinqdims(..., &dimNames[0], ...);   // overflows the string's heap buffer
```

### PoC

A crafted HDF-EOS swath file ```poc_swinqdims_bof.he4``` attached.

Vulerable path is demonstrated using built-in utility tool ```gdalmdiminfo``` built with ASan+UBSan:

```bash
ASAN_OPTIONS=detect_leaks=0 ./build/apps/gdalmdiminfo poc_swinqdims_bof.he4
```

ASan output:
```bash
==17850==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xe462d07e249e at pc 0xe732e06225f0 bp 0xffffc73f2180 sp 0xffffc73f1960
WRITE of size 9 at 0xe462d07e249e thread T0
    #0 0xe732e06225ec in strcat ../../../../src/libsanitizer/asan/asan_interceptors.cpp:520
    #1 0xe732d99258c4 in strcat /usr/include/aarch64-linux-gnu/bits/string_fortified.h:140
    #2 0xe732d99258c4 in SWinqdims /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/SWapi.c:1880
    #3 0xe732d9986460 in HDF4SwathGroup::GetDimensions(char const* const*) const /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf4multidim.cpp:1477
    #4 0xe732da9e9564 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1125
    #5 0xe732da9e9db4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #6 0xe732da9e9db4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #7 0xe732da9ed28c in GDALMultiDimInfo /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1360
    #8 0xb2750cdfeb3c in main /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_bin.cpp:83
    #9 0xe732d3a72598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #10 0xe732d3a72678 in __libc_start_main_impl ../csu/libc-start.c:360
    #11 0xb2750cdff0ec in _start (/home/roo/Desktop/gdal/build/apps/gdalmdiminfo+0x6f0ec) (BuildId: bf1bbb6a7dc6ab35d8312ba39c07c6f3cde7f417)

0xe462d07e249e is located 0 bytes after 350-byte region [0xe462d07e2340,0xe462d07e249e)
allocated by thread T0 here:
    #0 0xe732e062b17c in operator new(unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:86
    #1 0xe732d45384dc in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_mutate(unsigned long, unsigned long, char const*, unsigned long) (/lib/aarch64-linux-gnu/libstdc++.so.6+0x1684dc) (BuildId: a92c155807670007db0230c56786f6c4e7fad9b9)
    #2 0xe732d45393fc in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_replace_aux(unsigned long, unsigned long, unsigned long, char) (/lib/aarch64-linux-gnu/libstdc++.so.6+0x1693fc) (BuildId: a92c155807670007db0230c56786f6c4e7fad9b9)
    #3 0xe732d9986404 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::resize(unsigned long) /usr/include/c++/15/bits/basic_string.h:1216
    #4 0xe732d9986404 in HDF4SwathGroup::GetDimensions(char const* const*) const /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf4multidim.cpp:1476
    #5 0xe732da9e9564 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1125
    #6 0xe732da9e9db4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #7 0xe732da9e9db4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #8 0xe732da9ed28c in GDALMultiDimInfo /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1360
    #9 0xb2750cdfeb3c in main /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_bin.cpp:83
    #10 0xe732d3a72598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #11 0xe732d3a72678 in __libc_start_main_impl ../csu/libc-start.c:360
    #12 0xb2750cdff0ec in _start (/home/roo/Desktop/gdal/build/apps/gdalmdiminfo+0x6f0ec) (BuildId: bf1bbb6a7dc6ab35d8312ba39c07c6f3cde7f417)

SUMMARY: AddressSanitizer: heap-buffer-overflow /usr/include/aarch64-linux-gnu/bits/string_fortified.h:140 in strcat
Shadow bytes around the buggy address:
  0xe462d07e2200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe462d07e2280: 00 00 00 00 00 00 00 00 00 00 00 00 07 fa fa fa
  0xe462d07e2300: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0xe462d07e2380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xe462d07e2400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0xe462d07e2480: 00 00 00[06]fa fa fa fa fa fa fa fa fa fa fa fa
  0xe462d07e2500: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xe462d07e2580: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xe462d07e2600: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xe462d07e2680: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xe462d07e2700: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==17850==ABORTING
```

Impact:
  - Immediate:  Heap buffer overflow — SIGSEGV leadin to Denial of Service
  - Potential:  Controlled heap OOB write 
  - Scope:      Any application using GDAL's HDF4 / HDF-EOS multidimensional API
                to open a swath-format file.
