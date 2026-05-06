## CVE-2026-7233: Heap out-of-bounds read in fz_subset_cff_for_gids via off-by-one in index_load validation

index_load() in subset-cff.c validates that the last CFF INDEX offset does not
exceed the total CFF buffer length, but the memcpy in do_subset() reads using
absolute positions computed by index_get(), which adds the INDEX's data_offset.
Since data_offset > 0 for any INDEX that does not begin at byte 0 of the CFF,
a crafted CFF with v_last = len passes the validation check while
index_get(count) = data_offset + len > len, causing do_subset() to memcpy
past the end of the allocated CFF buffer.

Version: 1.28.0
Commit:  83dfcc08108cf38cf09f301361f38311559c68ef


### Root cause (subset-cff.c):
```c
    /* index_load(), line 315 — validation uses raw v */
    if (v > len)
        fz_throw(ctx, FZ_ERROR_FORMAT, "Truncated index");

    /* index_load(), line 297 — data_offset absorbs the INDEX base position */
    index->data_offset = data_offset + offset;   /* offset > 0 always */

    /* index_get(), line 337 — absolute position adds data_offset back */
    return index->data_offset + v;               /* = data_offset + len > len */

    /* do_subset(), line 800 — reads using the OOB absolute position */
    memcpy(strings + fill, &cff->base[offset], end - offset);
```

The check at line 315 compares the raw relative offset v against len (total
CFF size), but index_get() returns data_offset + v (an absolute file position).
With data_offset = 38 and v_last = len = 1040, index_get(count) = 1078, so
do_subset() reads 1039 bytes starting at position 39 of a 1041-byte allocation,
overflowing the heap right redzone by 37 bytes.


### Run:
```bash
    ASAN_OPTIONS=abort_on_error=0 \
    /path/to/mutool clean -S poc_bug_a.pdf /tmp/poc_out.pdf
```

### Sanitizer output:
```bash
$ ASAN_OPTIONS=abort_on_error=0 mutool clean -S poc_bug_a.pdf /tmp/poc_out.pdf 2>&1
library error: FT_New_Memory_Face(TestCID): unknown file format
warning: ignored error when loading embedded font; attempting to load system font
warning: non-embedded font using identity encoding: TestCID (mapping via TrueType-UCS2)
=================================================================
==124388==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdefc931e1391 at pc 0xe16c95637f5c bp 0xffffd16ff090 sp 0xffffd16fe870
READ of size 1039 at 0xdefc931e1391 thread T0
    #0 0xe16c95637f58 in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0xbcbb71154820  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0x1694820) (BuildId: 530630fd7b795b9d033648d1eb6ab3d6678434c6)
    #2 0xbcbb7115f568  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0x169f568)
    #3 0xbcbb70f61acc  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0x14a1acc)
    #4 0xbcbb70f63b30  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0x14a3b30)
    #5 0xbcbb70dd6268  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0x1316268)
    #6 0xbcbb70a2fab8  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0xf6fab8)
    #7 0xbcbb709a4274  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0xee4274)
    #8 0xe16c94792598 in __libc_start_call_main
    #9 0xe16c94792678 in __libc_start_main_impl
    #10 0xbcbb709a962c  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0xee962c)

0xdefc931e1391 is located 0 bytes after 1041-byte region [0xdefc931e0f80,0xdefc931e1391)
allocated by thread T0 here:
    #0 0xe16c9563a578 in malloc
    #1 0xbcbb70bf7238  (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0x1137238)
    ...

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/roo/Desktop/mupdf/mupdf/build/release/mutool+0x1694820) in memcpy


Shadow bytes around the buggy address:
  0xdefc931e1300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0xdefc931e1380: 00 00[01]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xdefc931e1400: fa fa fa fa ...
Shadow byte legend: 00=addressable, 01=partial (1 byte), fa=heap right redzone
```

### Impact:
  - Immediate:  DoS — mutool clean -S crashes on crafted PDF
  - Potential:  Info leak — 37+ bytes of heap memory immediately following the
                CFF allocation are copied verbatim into the output PDF's
                subsetted font stream, potentially exposing adjacent heap
                contents to the PDF consumer

