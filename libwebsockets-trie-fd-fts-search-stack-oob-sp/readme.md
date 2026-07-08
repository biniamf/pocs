## Missing bounds check on sp in lws_fts_search() allows stack buffer overflow via deep trie traversal

lib/misc/fts/trie-fd.c:865 increments the traversal stack pointer
'sp' without checking against the array size s[128]. During
autocomplete traversal, each trie level with children increments sp.
When the trie has depth >= 128, sp reaches 128 and the subsequent
memset(&s[128], 0, sizeof(s[0])) at line 866 writes 732 bytes past
the array boundary on the stack, corrupting adjacent local variables
(needle, path, lbuf, ebuf, buf).

Version: 4.5.99-v4.5.0-508-gb4b5aed39
Commit:  b4b5aed39


Root cause (lib/misc/fts/trie-fd.c:863-868):
```c
    /* line 403 -- fixed-size stack array */
    struct wac s[128];

    /* lines 863-868 -- sp++ without bounds check */
    if (!s[sp].done_children && children) {
        s[sp].done_children = 1;
        sp++;                                    /* line 865: NO CHECK */
        memset(&s[sp], 0, sizeof(s[sp]));        /* line 866: OOB WRITE */
        s[sp].tifs = fileofs_tif_start;          /* line 867 */
        s[sp].self = (jg2_file_offset)child_ofs; /* line 868 */
    }

    sizeof(struct wac) = 732 bytes (on 64-bit).
    When sp=128, memset writes 732 bytes past s[127] into:
      needle[32], path[256], lbuf[256], ebuf[384], buf[4096]
      -- all adjacent on the stack frame.
```

### Trigger:
```bash
    ./poc_fts_search_sp_oob
```
    The harness creates a valid FTS index with 140 words of the form
    "ax", "aax", "aaax", ..., "a^140x". Each word forces a branching
    point at a different trie depth. Searching for "a" triggers
    autocomplete traversal that descends all 140 levels, pushing sp
    to 128+ and triggering the OOB write.


### ASan output:
```bash
    ==295635==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffffe498ad30 at pc 0xe5e4a7be724c bp 0xffffe4973c50 sp 0xffffe4973430
    WRITE of size 732 at 0xffffe498ad30 thread T0
        #0 in memset
        #1 in lws_fts_search
        #2 in main poc_fts_search_sp_oob.c:140
        #3 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

    Address is located in stack of thread T0 at offset 94144 in frame
        #0 in lws_fts_search
      This frame has 28 object(s):
        [448, 94144) 's' (line 403) <== Memory access at offset 94144 overflows this variable

    SUMMARY: AddressSanitizer: stack-buffer-overflow in lws_fts_search
```

### Impact:

  - Stack buffer overflow -- 732 bytes written past s[128] into adjacent
    local variables (needle, path, lbuf, ebuf, buf) on the stack
  - DoS (crash) -- stack canary detection or ASan aborts the process
  - Potential code execution -- if the overflow reaches saved registers
  - Requires crafted FTS index file -- not triggerable from normal
    content; the index must contain words producing trie depth >= 128
  - Local attack vector only -- victim must open the crafted index file
