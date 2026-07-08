## Duplicate opus_decoder_destroy()/opus_encoder_destroy() calls in mixer_media_session_destroy() cause double-free heap corruption

plugins/protocol_lws_webrtc_mixer/mixer-media.c:198-202 contains two
identical pairs of opus_decoder_destroy() and opus_encoder_destroy()
calls. After the first pair frees the decoder and encoder objects, the
pointers are not set to NULL. The second pair re-evaluates the non-null
check (which passes on the now-dangling pointers) and frees the same
memory again, causing deterministic heap corruption.

The double-free is deterministic -- it occurs on every call to
mixer_media_session_destroy() when decoder or encoder pointers are
non-null. WebRTC sessions can be initiated remotely, making this
reachable by an unauthenticated network attacker who can establish
and tear down a WebRTC mixer session.

Version: 4.5.99-v4.5.0-508-gb4b5aed39 (current main)
Commit:  b4b5aed39


Root cause (plugins/protocol_lws_webrtc_mixer/mixer-media.c:198-202):
```c
    /* identical destroy calls, no NULL after first pair */
    if (s->decoder) opus_decoder_destroy(s->decoder);  /* line 198 -- OK */
    if (s->encoder) opus_encoder_destroy(s->encoder);  /* line 199 -- OK */

    if (s->decoder) opus_decoder_destroy(s->decoder);  /* line 201 -- DOUBLE FREE */
    if (s->encoder) opus_encoder_destroy(s->encoder);  /* line 202 -- DOUBLE FREE */

    opus_decoder_destroy/opus_encoder_destroy call free() internally.
    After line 198 frees s->decoder, the pointer value is unchanged.
    Line 201 checks (s->decoder != NULL) -- TRUE on dangling pointer.
    opus_decoder_destroy(s->decoder) calls free() on already-freed memory.
```

### Trigger:
```bash
    ./poc_opus_double_free
```
The harness creates real OpusDecoder and OpusEncoder objects via
libopus, stores them in a mixer_media_session struct, and invokes
the real mixer_media_session_destroy() function compiled from the
original mixer-media.c source.


ASan output:
```bash
    ==295560==ERROR: AddressSanitizer: attempting double-free on 0xe2986efdc800 in thread T0:
        #0 in free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:51
        #1 in mixer_media_session_destroy mixer-media.c:201
        #2 in main poc_opus_double_free.c:149
        #3 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

    0xe2986efdc800 is located 0 bytes inside of 141108-byte region
    freed by thread T0 here:
        #0 in free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:51
        #1 in mixer_media_session_destroy mixer-media.c:198
        #2 in main poc_opus_double_free.c:149

    previously allocated by thread T0 here:
        #0 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:67
        #1 in opus_decoder_create

    SUMMARY: AddressSanitizer: double-free mixer-media.c:201 in mixer_media_session_destroy
```

### Impact:

- Heap corruption -- double-free corrupts allocator metadata, leading
  to overlapping allocations and type confusion
- Remote code execution -- via tcache poisoning / fastbin dup,
  attacker-controlled audio data can overwrite function pointers
- DoS (crash) -- allocator double-free detection aborts process
- Remote trigger -- WebRTC sessions can be established by remote
  clients; session teardown triggers the vulnerable destroy path
- Deterministic -- no race condition or timing dependency; the
  double-free occurs on every destroy call when codecs are initialized

