## Out-of-bounds read in GDAL's vendored HDF-EOS library via size_t underflow in GDSDfldsrch

GDSDfldsrch (frmts/hdf4/hdf-eos/GDapi.c) strips quotes from a metadata-derived
string using memmove(name, name+1, strlen(name)-2) and name[strlen(name)-2]=0
without checking that strlen(name) >= 2.  When the FieldList metadata value is
empty (strlen=0), the expression strlen(name)-2 wraps to SIZE_MAX-1
(18446744073709551614) due to unsigned underflow, causing memmove to attempt a
read of ~18 exabytes from the stack — immediate crash.

Version: GDAL 3.13.0dev-4c681ad376
Commit:  4c681ad376


Root cause (GDapi.c):

```c
    EHgetmetavalue(metaptrs, "FieldList", name);  /* return status ignored */
    memmove(name, name + 1, strlen(name) - 2);    // <- SIZE_MAX-1 if name=""
    name[strlen(name) - 2] = 0;                   // <- same underflow
```
  strlen() returns size_t (unsigned). 0 - 2 = 0xFFFFFFFFFFFFFFFE on 64-bit. name is char name[2048] on the stack. The memmove reads SIZE_MAX-1 bytes starting at name+1, writing to name — catastrophic stack-buffer-overflow.


### PoC

Triggered via `gdalmdiminfo` using crafted grid file [poc_gdsdfldsrch_oob-read]()
```bash
  ASAN_OPTIONS=detect_leaks=0 ./gdalmdiminfo poc_gdsdfldsrch_oob-read.he4
```

ASan output:
```bash
==45773==ERROR: AddressSanitizer: unknown-crash on address 0xdfd09090e301
at pc 0xe3d09aa6f6c0 bp 0xfffff8086230 sp 0xfffff8086220
READ of size 18446744073709551614 at 0xdfd09090e301 thread T0
    #0 0xe3d09aa6f6bc in memmove /usr/include/aarch64-linux-gnu/bits/string_fortified.h:36
    #1 0xe3d09aa6f6bc in GDSDfldsrch /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/GDapi.c:1981
    #2 0xe3d09aa748e0 in GDfieldinfo /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/GDapi.c:1812
    #3 0xe3d09aaf03f8 in HDF4EOSGridSubGroup::OpenMDArray(...) const /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf4multidim.cpp:2140
    #4 0xe3d09bb54cc0 in DumpArrays /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1062
    #5 0xe3d09bb54cc0 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1151
    #6 0xe3d09bb537d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #7 0xe3d09bb537d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #8 0xe3d09bb537d4 in DumpGroup /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1175
    #9 0xe3d09bb56cac in GDALMultiDimInfo /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_lib.cpp:1360
    #10 0xb9ca7c52eb3c in main /home/roo/Desktop/gdal/gdal/apps/gdalmdiminfo_bin.cpp:83

Address 0xdfd09090e301 is located in stack of thread T0 at offset 769 in frame
    #0 0xe3d09aa6ea50 in GDSDfldsrch /home/roo/Desktop/gdal/gdal/frmts/hdf4/hdf-eos/GDapi.c:1875

  This frame has 5 object(s):
    [768, 2816) 'name' (line 1885) <== Memory access at offset 769

SUMMARY: AddressSanitizer: unknown-crash in memmove GDSDfldsrch GDapi.c:1981
```

### Impact:
  - Immediate:  DoS
