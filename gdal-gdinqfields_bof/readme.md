## Heap buffer overflow in GDAL's vendored HDF-EOS library via unbounded strcat in GDinqfields

GDinqfields (frmts/hdf4/hdf-eos/GDapi.c) appends data field names into a caller-provided buffer using repeated strcat without bounds checking. The caller in HDF4EOSGridSubGroup::GetMDArrayNames (hdf4multidim.cpp) sizes the buffer with GDnentries(), which subtracts 2 bytes per entry under the assumption that every DataFieldName value in the HDF-EOS metadata is double-quoted. When a crafted HDF-EOS file supplies unquoted DataFieldName values (which pass all HDF library validation), GDnentries undercounts the required buffer by 2 bytes per field entry while GDinqfields writes the full name length — producing a heap buffer overflow of 2*N bytes for N field entries.

- Version: GDAL 3.13.0dev-4c681ad376
- Commit:  4c681ad376

### Root cause:

GDnentries (GDapi.c):
```c
    EHgetmetavalue(metaptrs, &valName[i][0], utlstr);
    *strbufsize += (int32)strlen(utlstr) - 2;   // <- assumes value is quoted
```
The subtraction of 2 intends to strip the surrounding double quotes ("name").
When DataFieldName=value (no quotes), strlen(utlstr)=L and strbufsize grows by
L-2 instead of L.

GDinqfields (GDapi.c):
```c
    EHgetmetavalue(metaptrs, "OBJECT", utlstr);
    if (utlstr[0] != '"')
    {
        // new metadata: search for DataFieldName=
        metaptrs[0] = strstr(metaptrs[0], "\t\t\t\tDataFieldName=");
        EHgetmetavalue(metaptrs, "DataFieldName", utlstr);
    }
    REMQUOTE(utlstr);           // no-op: first char is not '"'
    if (nFld > 0)
        strcat(fieldlist, ",");
    strcat(fieldlist, utlstr);  // <- writes L bytes, but only L-2 were counted
```
Caller (hdf4multidim.cpp):
```c
    GDnentries(handle, HDFE_NENTDFLD, &nStrBufSize);
    osFieldList.resize(nStrBufSize);                    // undersized allocation
    GDinqfields(handle, &osFieldList[0], ...);          // OVERFLOW
```

### PoC

A crafted HDF-EOS swath file ```poc_gdinqfields_bof.he4``` attached.

```c
  ASAN_OPTIONS=detect_leaks=0 ./gdalmdiminfo poc_gdinqfields_bof.he4
```

ASan output:
```bash
==61167==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xf6ba73de281e at pc 0xf98a83e225f0 bp 0xffffd6d7d480 sp 0xffffd6d7cc60
WRITE of size 9 at 0xf6ba73de281e thread T0
    #0 0xf98a83e225ec in strcat ../../../../src/libsanitizer/asan/asan_interceptors.cpp:520
    #1 0xf98a7cff8154 in strcat /usr/include/aarch64-linux-gnu/bits/string_fortified.h:140
    #2 0xf98a7cff8154 in GDinqfields /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/GDapi.c:2947
    #3 0xf98a7d062618 in HDF4EOSGridSubGroup::GetMDArrayNames[abi:cxx11](char const* const*) const /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf4multidim.cpp:2109
    #4 0xf98a7e0d31fc in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1147
    #5 0xf98a7e0d37d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #6 0xf98a7e0d37d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #7 0xf98a7e0d37d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #8 0xf98a7e0d6cac in GDALMultiDimInfo /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1360
    #9 0xba79c54aeb3c in main /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_bin.cpp:83
    #10 0xf98a76fe2598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #11 0xf98a76fe2678 in __libc_start_main_impl ../csu/libc-start.c:360
    #12 0xba79c54af0ec in _start (/home/roo/Desktop/gdal/build/apps/gdalmdiminfo+0x6f0ec) (BuildId: d380a6aa207c1cafd76aa2a9708be7bd7f541369)

0xf6ba73de281e is located 0 bytes after 350-byte region [0xf6ba73de26c0,0xf6ba73de281e)
allocated by thread T0 here:
    #0 0xf98a83e2b17c in operator new(unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:86
    #1 0xf98a77aa84dc in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_mutate(unsigned long, unsigned long, char const*, unsigned long) (/lib/aarch64-linux-gnu/libstdc++.so.6+0x1684dc) (BuildId: a92c155807670007db0230c56786f6c4e7fad9b9)
    #2 0xf98a77aa93fc in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_replace_aux(unsigned long, unsigned long, unsigned long, char) (/lib/aarch64-linux-gnu/libstdc++.so.6+0x1693fc) (BuildId: a92c155807670007db0230c56786f6c4e7fad9b9)
    #3 0xf98a7d06250c in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::resize(unsigned long) /usr/include/c++/15/bits/basic_string.h:1216
    #4 0xf98a7d06250c in HDF4EOSGridSubGroup::GetMDArrayNames[abi:cxx11](char const* const*) const /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf4multidim.cpp:2104
    #5 0xf98a7e0d31fc in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1147
    #6 0xf98a7e0d37d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #7 0xf98a7e0d37d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #8 0xf98a7e0d37d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #9 0xf98a7e0d6cac in GDALMultiDimInfo /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1360
    #10 0xba79c54aeb3c in main /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_bin.cpp:83
    #11 0xf98a76fe2598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #12 0xf98a76fe2678 in __libc_start_main_impl ../csu/libc-start.c:360
    #13 0xba79c54af0ec in _start (/home/roo/Desktop/gdal/build/apps/gdalmdiminfo+0x6f0ec) (BuildId: d380a6aa207c1cafd76aa2a9708be7bd7f541369)

SUMMARY: AddressSanitizer: heap-buffer-overflow /usr/include/aarch64-linux-gnu/bits/string_fortified.h:140 in strcat
Shadow bytes around the buggy address:
  0xf6ba73de2580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf6ba73de2600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fa
  0xf6ba73de2680: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0xf6ba73de2700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf6ba73de2780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0xf6ba73de2800: 00 00 00[06]fa fa fa fa fa fa fa fa fa fa fa fa
  0xf6ba73de2880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf6ba73de2900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf6ba73de2980: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf6ba73de2a00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf6ba73de2a80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==61167==ABORTING
```

Impact:
  - Immediate:  Heap buffer overflow leading to DoS
  - Potential:  Controlled heap OOB write.
  - Scope:      Any application using GDAL's HDF4 / HDF-EOS multidimensional to open a grid-format file.

