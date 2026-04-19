## Out-of-bounds read in GDAL's vendored HDF-EOS library via size_t underflow in GDfieldinfo

GDfieldinfo (frmts/hdf4/hdf-eos/GDapi.c) strips parentheses from a DimList metadata value using memmove(utlstr, utlstr+1, strlen(utlstr)-2) and utlstr[strlen(utlstr)-2]=0 without checking that strlen(utlstr) >= 2. When a crafted HDF-EOS grid file supplies an empty or single-character DimList value, strlen(utlstr)-2 wraps to SIZE_MAX-1 (unsigned underflow), causing memmove to attempt a read of ~18 exabytes — immediate crash.

- Version: GDAL 3.13.0dev-4c681ad376
- Commit:  4c681ad376


### Root cause (GDapi.c):
  ```c
    statmeta = EHgetmetavalue(metaptrs, "DimList", utlstr);
    if (statmeta == 0)
    {
        memmove(utlstr, utlstr + 1, strlen(utlstr) - 2);  // <- SIZE_MAX-1
        utlstr[strlen(utlstr) - 2] = 0;                   // <- same underflow
        ...
  ```
  The code assumes DimList is always parenthesized: ("dim1","dim2").
  It strips the leading "(" and trailing ")" via memmove with length
  strlen()-2.  If DimList is empty or single-char, strlen()-2 wraps to
  SIZE_MAX due to unsigned arithmetic (size_t).

  utlstr is a 512-byte heap buffer (calloc'd at line 1694).  The memmove
  reads SIZE_MAX-1 bytes starting at utlstr+1, far beyond the allocation.

### PoC

The vulnerability is reachable from gdalmdiminfo via a crafted HDF-EOS grid file: ```poc_gdfinfo_dimlist_oobwrite.he4```.

```bash

ASAN_OPTIONS=detect_leaks=0 ./gdalmdiminfo poc_gdfinfo_dimlist_oobwrite.he4
```

ASan output:

```bash
==58568==ERROR: AddressSanitizer: unknown-crash on address 0xf54909de5801
at pc 0xf7f9130752dc bp 0xffffda2e4290 sp 0xffffda2e4280
READ of size 18446744073709551614 at 0xf54909de5801 thread T0
    #0 0xf7f9130752d8 in memmove /usr/include/aarch64-linux-gnu/bits/string_fortified.h:36
    #1 0xf7f9130752d8 in GDfieldinfo /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/GDapi.c:1756
    #2 0xf7f9130f03f8 in HDF4EOSGridSubGroup::OpenMDArray(...) const /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf4multidim.cpp:2140
    #3 0xf7f914154cc0 in DumpArrays /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1062
    #4 0xf7f914154cc0 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1151
    #5 0xf7f9141537d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #6 0xf7f9141537d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #7 0xf7f9141537d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #8 0xf7f914156cac in GDALMultiDimInfo /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1360
    #9 in main /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_bin.cpp:83

0xf54909de5801 is located 1 bytes inside of 512-byte region [0xf54909de5800,0xf54909de5a00)
allocated by thread T0 here:
    #0 in calloc
    #1 0xf7f913073e94 in GDfieldinfo /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/GDapi.c:1694

SUMMARY: AddressSanitizer: unknown-crash in memmove GDfieldinfo GDapi.c:1756

```

### Impact:
  - Immediate:  SIGSEGV leading to DoS
