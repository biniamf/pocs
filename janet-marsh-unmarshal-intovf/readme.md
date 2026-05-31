## CVE-2026-10267: Signed integer overflow in fiber deserialization leads to allocation-size corruption

unmarshal_one_fiber() in marsh.c computes fiber->capacity = fiber_stacktop + 10
(line 1114) where fiber_stacktop is read directly from attacker-controlled
serialized data via readnat(). readnat() returns values up to INT32_MAX
(2147483647). No overflow check guards the addition.

When fiber_stacktop = INT32_MAX, the addition overflows signed int32:
  2147483647 + 10 → undefined behavior (signed overflow)
  wraps to -2147483639 (0x80000009) in practice

The corrupted capacity is then used in:
```c  
janet_malloc(sizeof(Janet) * fiber->capacity)     /* line 1115 */
```

On 64-bit: the negative int32 sign-extends to size_t 0xFFFFFFFF80000009,
producing a malloc request of 0xFFFFFFFC00000048 bytes (~18 exabytes).
ASan reports allocation-size-too-big.

On 32-bit: sizeof(Janet) * (uint32_t)0x80000009 wraps to a small value,
producing a tiny heap allocation. Subsequent writes to fiber->data from
deserialized stack data overflow the undersized buffer — a directly
exploitable heap buffer overflow.

The validation checks (line 1107-1110) do not prevent this because
fiber_maxstack is also attacker-controlled and can be set to INT32_MAX,
satisfying fiber_stacktop <= fiber_maxstack.

Version: 1.41.0 (commit 5b5844b4)

### Root cause (marsh.c):
```c
    /* line 1102 — attacker-controlled via readnat(), range [0, INT32_MAX] */
    int32_t fiber_stacktop = readnat(st, &data);
    int32_t fiber_maxstack = readnat(st, &data);

    /* line 1107 — validation passes when both are INT32_MAX */
    if (fiber_stacktop > fiber_maxstack)
        janet_panic("fiber has incorrect stack setup");

    /* line 1114 — OVERFLOW: INT32_MAX + 10 wraps signed int32 */
    fiber->capacity = fiber_stacktop + 10;

    /* line 1115 — corrupted capacity used for allocation */
    fiber->data = janet_malloc(sizeof(Janet) * fiber->capacity);
```

### PoC (attached files):  
`poc_marsh_fiber_intovf.bin`

### Run:
```bash
    ./build/janet -e '(unmarshal (slurp "poc_marsh_fiber_intovf.bin"))'
```

### Build with sanitizers:
```bash
    cd janet
    make clean
    make CFLAGS="-O2 -g -fsanitize=address,undefined" \
         LDFLAGS="-rdynamic -fsanitize=address,undefined"
```

### Sanitizer output:
```bash
$ UBSAN_OPTIONS=print_stacktrace=1 ASAN_OPTIONS=print_stacktrace=1 \
    ./build/janet -e '(unmarshal (slurp "poc_marsh_fiber_intovf.bin"))' 2>&1
src/core/marsh.c:1114:38: runtime error: signed integer overflow: 2147483647 + 10 cannot be represented in type 'int'
    #0 in unmarshal_one_fiber src/core/marsh.c:1114
    #1 in unmarshal_one src/core/marsh.c:1409
    #2 in janet_unmarshal src/core/marsh.c:1649
    #3 in run_vm src/core/vm.c:1061
    #4 in janet_continue_no_check src/core/vm.c:1579

=================================================================
==PID==ERROR: AddressSanitizer: requested allocation size 0xfffffffc00000048 (after adjustments) exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 in malloc
    #1 in unmarshal_one_fiber src/core/marsh.c:1115
    #2 in unmarshal_one src/core/marsh.c:1409
    #3 in janet_unmarshal src/core/marsh.c:1649
    #4 in run_vm src/core/vm.c:1061
    #5 in janet_continue_no_check src/core/vm.c:1579

SUMMARY: AddressSanitizer: allocation-size-too-big src/core/marsh.c:1115 in unmarshal_one_fiber
```

### Impact:
  - Immediate:  DoS — any Janet program calling unmarshal on untrusted data
                crashes (OOM abort on 64-bit, heap corruption on 32-bit)
  - 32-bit:     Heap buffer overflow — undersized allocation with large
                write loop enables heap corruption and potential RCE
  - 64-bit:     The overflow is undefined behavior; compiler may optimize
                assuming no overflow, potentially eliminating safety checks

