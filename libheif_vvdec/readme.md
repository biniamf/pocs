Out-of-Bounds Read in `vvdec_push_data2()` Due to Missing Length Validation

An out-of-bounds read vulnerability exists in `plugins/decoder_vvdec.cc` within the NAL unit parsing logic. The function parses a 32-bit NAL unit size from the input buffer and then copies `size` bytes into a vector without verifying that sufficient data remains in the buffer. An attacker could craft a HEIF file whose compressed data extent contains a length-prefixed NAL unit where the declared length exceeds the actual available data causing an out-of-bounds read.

# Vulnerable code

```c
// libheif/plugins/decoder_vvdec.cc, lines 175–202
heif_error vvdec_push_data2(void* decoder_raw, const void* frame_data, size_t frame_size,
                            uintptr_t user_data)
{
  auto* decoder = (vvdec_decoder*) decoder_raw;
  const auto* data = (const uint8_t*) frame_data;

  for (;;) {
    // BUG 1: No check that frame_size >= 4 before reading data[0..3]
    uint32_t size = four_bytes_to_uint32(data[0], data[1], data[2], data[3]);

    data += 4;

    std::vector<uint8_t> nalu;
    nalu.push_back(0);
    nalu.push_back(0);
    nalu.push_back(1);
    // BUG 2: No check that [size <= frame_size - 4] before copying
    nalu.insert(nalu.end(), data, data + size);   // <-- potential OOB READ here

    decoder->nalus.push_back({std::move(nalu), user_data});
    data += size;
    frame_size -= 4 + size;   // BUG 3: unsigned underflow if size > frame_size - 4
    if (frame_size == 0) {
      break;
    }
  }

  return heif_error_ok;
}
```

It seems like there's a similar function in `decoder_libde265.cc`,  `libde265_v1_push_data2()` but with a proper guard is implemented:

```c
    if (4 > size - ptr) {
      return {
        heif_error_Decoder_plugin_error,
        heif_suberror_End_of_data,
        ...
```

## POC

A minimal but structurally valid HEIF file: [POC]()

| Field              | Value |
|--------------------|-------|
| OS                 | Ubuntu Linux 6.17.0-14-generic aarch64 |
| Compiler           | g++ (Ubuntu 15.2.0-4ubuntu4) 15.2.0 |
| CMake              | 3.31.6 |
| libheif commit     | `8b62c5088a7ad02b81682e97dfbfbcc8fbca2a0f` |
| libheif version    | 1.21.2 |
| vvdec version      | 3.2.0-dev (built from source, static) |

```bash
cmake -S libheif -B build \
  -DWITH_VVDEC=ON \
  -DCMAKE_PREFIX_PATH="$(pwd)/vvdec/dist" \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build --parallel $(nproc)

ASAN_OPTIONS=halt_on_error=1:detect_leaks=0 \
  ./build/examples/heif-dec poc_vvdec_oob_read.heif /tmp/out.y4m
```


```
=================================================================
==7333==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdff2675e0718 at pc 0xe3d26e317f5c bp 0xfffff3fdc650 sp 0xfffff3fdbe30
READ of size 16 at 0xdff2675e0718 thread T0
    #0 0xe3d26e317f58 in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0xe3d26ad9b81c in unsigned char* std::uninitialized_copy<unsigned char const*, unsigned char*>(unsigned char const*, unsigned char const*, unsigned char*)
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x1dcb81c)
    #2 0xe3d26ad6dcb4 in unsigned char* std::__uninitialized_copy_a<unsigned char const*, unsigned char const*, unsigned char*, unsigned char>(...)
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x1d9dcb4)
    #3 0xe3d26b0e344c in void std::vector<unsigned char>::_M_range_insert<unsigned char const*>(...)
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x211344c)
    #4 0xe3d26b0e03f0 in std::vector<unsigned char>::insert(...)
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x21103f0)
    #5 0xe3d26b6b67d8 in vvdec_push_data2(void*, void const*, unsigned long, unsigned long)
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x26e67d8)
    #6 0xe3d26b1c5cf0 in Decoder::decode_sequence_frame_from_compressed_data(bool, heif_decoding_options const&, unsigned long, heif_security_limits const*)
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x21f5cf0)
    #7 0xe3d26b1c8e38 in Decoder::decode_single_frame_from_compressed_data(heif_decoding_options const&, heif_security_limits const*)
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x21f8e38)
    #8 0xe3d26b3276b4 in ImageItem::decode_compressed_image(heif_decoding_options const&, bool, unsigned int, unsigned int, std::set<unsigned int, std::less<unsigned int>, std::allocator<unsigned int> >) const
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x23576b4)
    #9 0xe3d26b3210b0 in ImageItem::decode_image(heif_decoding_options const&, bool, unsigned int, unsigned int, std::set<unsigned int, std::less<unsigned int>, std::allocator<unsigned int> >) const
       (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x23510b0)
    #10 0xe3d26aeb5894 in HeifContext::decode_image(unsigned int, heif_colorspace, heif_chroma, heif_decoding_options const&, bool, unsigned int, unsigned int, std::set<unsigned int, std::less<unsigned int>, std::allocator<unsigned int> >) const
        (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x1ee5894)
    #11 0xe3d26b189454 in heif_decode_image
        (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x21b9454)
    #12 0xb403e6625d28 in decode_single_image(heif_image_handle*, std::string, std::string, heif_decoding_options*, std::unique_ptr<Encoder>&)
        (/home/roo/Desktop/libheif/build/examples/heif-dec+0x55d28)
    #13 0xb403e6633b3c in main
        (/home/roo/Desktop/libheif/build/examples/heif-dec+0x63b3c)
    #14 0xe3d2683d2598 in __libc_start_call_main
    #15 0xe3d2683d2678 in __libc_start_main_impl
    #16 0xb403e662406c in _start

0xdff2675e0718 is located 0 bytes after 8-byte region [0xdff2675e0710,0xdff2675e0718)
allocated by thread T0 here:
    #0 0xe3d26e31b17c in operator new(unsigned long)
       ../../../../src/libsanitizer/asan/asan_new_delete.cpp:86
    #1  (std::vector<uint8_t> internal allocation for the 8-byte frame buffer
        assembled in Decoder::get_compressed_data)

SUMMARY: AddressSanitizer: heap-buffer-overflow
  (/home/roo/Desktop/libheif/build/libheif/libheif.so.1+0x1dcb81c)
  in unsigned char* std::uninitialized_copy<unsigned char const*, unsigned char*>(...)

Shadow bytes around the buggy address:
  0xdff2675e0480: fa fa 01 fa fa fa 01 fa fa fa fd fd fa fa fd fa
  0xdff2675e0500: fa fa fd fa fa fa 00 fa fa fa fd fd fa fa fd fd
  0xdff2675e0580: fa fa fd fd fa fa fd fa fa fa fd fd fa fa 00 00
  0xdff2675e0600: fa fa fd fd fa fa fd fd fa fa 04 fa fa fa fd fd
  0xdff2675e0680: fa fa 00 fa fa fa 00 fa fa fa 00 fa fa fa 00 fa
=>0xdff2675e0700: fa fa 00[fa]fa fa fd fa fa fa fd fa fa fa 04 fa
  0xdff2675e0780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  ...
Shadow byte legend:
  Addressable:       00   Heap left redzone:  fa
  Heap right redzone: fa  Freed heap region:  fd
==7333==ABORTING
```