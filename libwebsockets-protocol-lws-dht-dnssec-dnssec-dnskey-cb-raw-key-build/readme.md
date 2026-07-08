## Missing bounds check on JWK key component lengths in DNSSEC DNSKEY construction causes stack buffer overflow

plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c:655-698
constructs DNSSEC key material in a fixed 1024-byte stack buffer
(key_data[1024]) by copying RSA key components from a parsed JWK
structure via memcpy without validating that the total length fits.
lws_jwk_import() accepts up to 512 bytes per RSA element
(LWS_JWE_LIMIT_KEY_ELEMENT_BYTES). With E=512 and N=512, the
combined key_data construction totals 4+3+512+512 = 1031 bytes,
overflowing key_data[1024] by 7 bytes. A malicious DNS server can
supply a crafted DNSKEY response containing a JWS with an embedded
RSA JWK using maximum-sized E and N components.

Version: 4.5.99-v4.5.0-508-gb4b5aed39 (current main)
Commit:  b4b5aed39


Root cause (plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c:655-698):
```c
    /* line 655 -- 1024-byte stack buffer */
    uint8_t key_data[1024];
    size_t key_len = 0;

    /* lines 658-661 -- 4-byte DNSKEY header */
    key_data[key_len++] = 257 >> 8;     /* Flags */
    key_data[key_len++] = 257 & 0xff;
    key_data[key_len++] = 3;            /* Protocol */
    key_data[key_len++] = frag->algo;   /* Algorithm */

    /* lines 668-686 -- RSA exponent (E), no combined bounds check */
    if (e_len <= 255) {
        key_data[key_len++] = (uint8_t)e_len;
    } else {
        key_data[key_len++] = 0;        /* 3-byte prefix for E>255 */
        key_data[key_len++] = (uint8_t)(e_len >> 8);
        key_data[key_len++] = (uint8_t)(e_len & 0xff);
    }
    memcpy(key_data + key_len, e_buf, e_len);   /* line 685 */
    key_len += e_len;

    /* lines 697-698 -- RSA modulus (N), no combined bounds check */
    memcpy(key_data + key_len, n_buf, n_len);   /* line 697 <- OVERFLOW */
    key_len += n_len;

    /* With E=512, N=512 (both at lws_jwk_import per-element limit):
     *   key_len = 4 (header) + 3 (E prefix) + 512 (E) + 512 (N) = 1031
     *   Overflow: 1031 - 1024 = 7 bytes past key_data[]
     */
```

### Trigger:

  Build (requires libwebsockets built with -DLWS_WITH_JOSE=ON):
  ```bash
    gcc -fsanitize=address,undefined -fno-omit-frame-pointer \
      -I<lws_build>/include -I<lws_src>/include \
      -I<lws_src>/plugins/protocol_lws_dht_dnssec \
      -include protocol_lws_dht_dnssec.c \
      -Wno-unused-function \
      poc_dnssec_key_overflow.c \
      -L<lws_build>/lib -lwebsockets \
      -lssl -lcrypto -lpthread -lm -luv -l:libcap.so.2 \
      -o poc_dnssec_key_overflow

    ./poc_dnssec_key_overflow
 ```
  The harness compiles the real plugin source code
  (protocol_lws_dht_dnssec.c). JWK parsing uses the
  real lws_jwk_import() from libwebsockets. It creates a
  JWS file with an RSA JWK containing E=512 and N=512 byte
  components — both within the per-element limit but together
  exceeding key_data[1024].


### ASan output:
```bash
    ==304757==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xe5ae84901ac0 at pc 0xe9ae87ae7d80 bp 0xffffcb58eb30 sp 0xffffcb58e310
    WRITE of size 512 at 0xe5ae84901ac0 thread T0
        #0 in memcpy
        #1 in dht_dnssec_dnskey_cb protocol_lws_dht_dnssec.c:697
        #2 in main poc_dnssec_key_overflow.c:204
        #3 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

    Address is located in stack of thread T0 at offset 6848 in frame
        #0 in dht_dnssec_dnskey_cb protocol_lws_dht_dnssec.c:519
      This frame has 32 object(s):
        [5824, 6848) 'key_data' (line 655) <== Memory access at offset 6848 overflows this variable
        [6976, 8000) 'cpath' (line 1015) <== Memory access at offset 6848 partially underflows this variable

    SUMMARY: AddressSanitizer: stack-buffer-overflow protocol_lws_dht_dnssec.c:697 in dht_dnssec_dnskey_cb
```

### Impact:

  - Stack buffer overflow -- 7 bytes past key_data[1024] into
    adjacent stack variable (cpath[1024])
  - Remote trigger -- attacker controls JWK key material via
    malicious DNS server returning crafted DNSKEY responses
  - Preconditions -- requires RSA JWK with both E and N at
    maximum per-element size (512 bytes each); standard RSA
    keys (E=3 bytes, N≤512 bytes) fit within the buffer
  - DoS (crash) -- stack corruption causes process abort

