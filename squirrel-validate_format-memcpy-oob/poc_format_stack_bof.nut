// PoC for SQSTDSTRING-VALIDATE_FORMAT-MEMCPY-OOB
// Stack buffer overflow in validate_format() due to off-by-one length check.
//
// validate_format() uses MAX_FORMAT_LEN (20) as buffer size.
// The check "if (n-start > MAX_FORMAT_LEN)" uses > instead of >=,
// allowing n-start == 20. The memcpy then writes 21 bytes into &fmt[1],
// overflowing the 20-byte stack buffer by 3 bytes.
//
// Format: 13 flags + 3 width digits + '.' + 3 precision digits = 20 chars
// This is a valid printf format specifier, not API misuse.

format("%+-#0+-#0+-#0+-#99.99f", 1.0)
