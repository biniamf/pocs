## Out-of-bounds read in GDAL's vendored HDF-EOS library via size_t underflow in SWfinfo

SWfinfo (frmts/hdf4/hdf-eos/SWapi.c) strips parentheses from a DimList metadata value using memmove(utlstr, utlstr+1, strlen(utlstr)-2) and utlstr[strlen(utlstr)-2]=0 without checking that strlen(utlstr) >= 2. When a crafted HDF-EOS swath file supplies an empty or single-character DimList value, strlen(utlstr)-2 wraps to SIZE_MAX-1 (unsigned underflow), causing memmove to attempt a read of ~18 exabytes — immediate crash.


- Version: GDAL 3.13.0dev-4c681ad376
- Commit:  4c681ad376


Root cause (SWapi.c):
```c
    statmeta = EHgetmetavalue(metaptrs, "DimList", utlstr);
    if (statmeta == 0)
    {
        memmove(utlstr, utlstr + 1, strlen(utlstr) - 2);  // <- SIZE_MAX-1
        utlstr[strlen(utlstr) - 2] = 0;                   // <- same underflow
 ```
  The code assumes DimList is always parenthesized: ("dim1","dim2").
  It strips the leading "(" and trailing ")" via memmove with length
  strlen()-2.  If DimList is empty or single-char, strlen()-2 wraps to
  SIZE_MAX due to unsigned arithmetic (size_t).

  utlstr is a 512-byte heap buffer (calloc'd at line 1228).  The memmove
  reads SIZE_MAX-1 bytes starting at utlstr+1, far beyond the allocation.


### PoC

The vulnerability is reachable from gdalmdiminfo via a crafted HDF-EOS grid file: [poc_swfinfo_dimlist_oobwrite]()

```bash
  ASAN_OPTIONS=detect_leaks=0 ./gdalmdiminfo poc_swfinfo_dimlist_oobwrite.he4
```

ASan output:
```c
==58565==ERROR: AddressSanitizer: unknown-crash on address 0xf04394de6481
at pc 0xf2f39e03a268 bp 0xffffd00d5cd0 sp 0xffffd00d5cc0
READ of size 18446744073709551614 at 0xf04394de6481 thread T0
    #0 0xf2f39e03a264 in memmove /usr/include/aarch64-linux-gnu/bits/string_fortified.h:36
    #1 0xf2f39e03a264 in SWfinfo /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/SWapi.c:1304
    #2 0xf2f39e03b950 in SWfieldinfo /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/SWapi.c:1479
    #3 0xf2f39e0cc15c in HDF4SwathSubGroup::OpenMDArray(...) const /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf4multidim.cpp:1414
    #4 0xf2f39f104cc0 in DumpArrays /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1062
    #5 0xf2f39f104cc0 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1151
    #6 0xf2f39f1037d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #7 0xf2f39f1037d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #8 0xf2f39f1037d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #9 0xf2f39f106cac in GDALMultiDimInfo /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1360
    #10 in main /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_bin.cpp:83

0xf04394de6481 is located 1 bytes inside of 512-byte region [0xf04394de6480,0xf04394de6680)
allocated by thread T0 here:
    #0 in calloc
    #1 0xf2f39e038d18 in SWfinfo /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/SWapi.c:1228

SUMMARY: AddressSanitizer: unknown-crash in memmove SWfinfo SWapi.c:1304
```

### Impact:
  - Immediate:  DoS
