## Write-before-check in LECP literal CBOR recording allows 1-byte OOB write past ctx->cbor[] into ctx->item

lib/misc/lecp.c:391 writes ctx->cbor[ctx->cbor_pos++] = c before
checking whether cbor_pos has reached sizeof(ctx->cbor) at line 392.
When report_raw_cbor() is invoked because the buffer is full and the
application callback rejects the LECPCB_LITERAL_CBOR event,
report_raw_cbor() returns 1 WITHOUT resetting cbor_pos. The parser
then returns LECP_REJECT_CALLBACK with cbor_pos still at 64. If
lecp_parse() is called again with literal_cbor_report still enabled,
the first byte writes to ctx->cbor[64] -- overflowing into the
adjacent struct lecp_item member.

Version: 4.5.99-v4.5.0-508-gb4b5aed39 (current main)
Commit:  b4b5aed39


Root cause (lib/misc/lecp.c:390-394):
```c
    /* write-before-check pattern */
    if (ctx->literal_cbor_report) {
        ctx->cbor[ctx->cbor_pos++] = c;            /* line 391: WRITE FIRST */
        if (ctx->cbor_pos == sizeof(ctx->cbor) &&   /* line 392: CHECK AFTER */
            report_raw_cbor(ctx))                   /* line 393 */
            goto reject_callback;                   /* line 394 */
    }

    /* report_raw_cbor() does NOT reset cbor_pos on callback rejection */
    report_raw_cbor(struct lecp_ctx *ctx)            /* line 321 */
    {
        if (!ctx->cbor_pos)                          /* line 325 */
            return 0;
        if (pst->cb(ctx, LECPCB_LITERAL_CBOR))       /* line 328 */
            return 1;                                /* RETURNS WITHOUT RESET */
        ctx->cbor_pos = 0;                           /* line 331: only on success */
        return 0;
    }

    /* struct layout (lws-lecp.h:261-263) */
    uint8_t cbor[64];           /* line 261 */
    struct lecp_item item;      /* line 263 -- immediately after cbor[] */
```

### Trigger:
```bash
    ./poc_lecp_cbor_pos_oob
```
The harness enables literal_cbor_report via the public
lecp_parse_report_raw() API, feeds 66 bytes of CBOR to fill cbor[],
rejects the LECPCB_LITERAL_CBOR callback, then retries lecp_parse()
with 1 byte (0xDE). This byte is written to ctx->cbor[64], which is
the first byte of ctx->item.


### UBSan output:
```bash
    lecp.c:391:13: runtime error: index 64 out of bounds for type 'uint8_t [64]'
```

### Impact:

- Controlled write -- attacker chooses any byte value 0x00-0xFF to
  write past cbor[] into ctx->item (6/6 tests confirmed)
- Type confusion -- corrupted item opcode causes parser to
  misinterpret subsequent CBOR data types
- Remotely triggerable -- if the application parses untrusted CBOR
  with literal reporting enabled (e.g., COSE signature processing)
- Narrow trigger conditions -- requires callback rejection + retry
