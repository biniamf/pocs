
Note: we use the same poc file as in the QueryRGBBufferSizeInternal bug. 
With unpatched code, the crash manifests as the [QueryRGBBufferSize 
overflow](https://github.com/biniamf/pocs/tree/main/oiio-dpxcolorconverter-dpx-queryrgbbuffersize-intovf). After that fix is applied, the same file crashes at
SwapRGBABytes line 45.

A signed 32-bit integer overflow in the loop index expression `i * 4` inside SwapRGBABytes() causes the function to compute a large negative pointer offset when processing kABGR DPX images with large dimensions. The immediate crash is an
out-of-bounds **read** (the `memcpy` at line 45 reads from `&input[i * 4]` first), but the subsequent write operations at lines 46–49 target the same wrapped offset — making this a combined OOB read+write primitive. This bug is independent of and distinct from the QueryRGBBufferSizeInternal overflow reported previously.

- Version: 3.2.0.1-dev
- Commit:  c75e31faa1bc24dea923c03a51db7be78b71c660


Root cause (DPXColorConverter.cpp:41-50):
```c
template <typename DATA>
static inline bool SwapRGBABytes(const DATA *input, DATA *output, int pixels) {
    DATA tmp[2];
    for (int i = 0; i < pixels; i++) {
        memcpy(tmp, &input[i * 4], sizeof(DATA) * 2);   // ← i*4 overflow
        output[i * 4 + 0] = input[i * 4 + 3];           // ← i*4 overflow
        output[i * 4 + 1] = input[i * 4 + 2];
        output[i * 4 + 2] = tmp[1];
        output[i * 4 + 3] = tmp[0];
    }
    return true;
}
```
`pixels` is declared as `int` and is computed from Width * Height. When pixels
exceeds INT_MAX/4 = 536,870,911, the expression `i * 4` overflows at iteration
i = 536,870,912, producing a large negative signed value used as a pointer offset:
```
    i * 4 = 2,147,483,648   ->  int32 wrap = -2,147,483,648
    &output[-2,147,483,648] ->  write ~8 GB before buffer base → SEGV
```

### Proof-of-concept

PoC (attached .dpx file, ~2.1 GB sparse): poc_dpx_abgr_oob.dpx

### Run:
```bash
  ./bin/oiiotool --hash poc_dpx_abgr_oob.dpx
  # or
  ./bin/iinfo   --hash poc_dpx_abgr_oob.dpx
```

#### Sanitizer output (after the QueryRGBBufferSizeInternal bug is fixed, SwapRGBABytes crash at line 45):

```bash
$ ./bin/oiiotool --hash poc_dpx_abgr_oob.dpx 2>&1
/home/roo/Desktop/OpenImageIO/OpenImageIO/src/dpx.imageio/libdpx/DPXColorConverter.cpp:47:25: runtime error: signed integer overflow: 536870912 * 4 cannot be represented in type 'int'
AddressSanitizer:DEADLYSIGNAL
=================================================================
==235875==ERROR: AddressSanitizer: SEGV on unknown address 0xea154d62e800 (pc 0xee165b822060 bp 0xffffce8f2900 sp 0xffffce8f1fc0 T0)
==235875==The signal is caused by a READ memory access.
    #0 0xee165b822060 in dpx::ConvertToRGBInternal(dpx::Descriptor, dpx::DataSize, dpx::Characteristic, void const*, void*, int) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x7832060) (BuildId: fbc8ef25b27a6273f983f514d6b252a3c5aba2ad)
    #1 0xee165b72cc14 in OpenImageIO::v3_2_0::DPXInput::read_native_scanlines(int, int, int, int, int, void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x773cc14) (BuildId: fbc8ef25b27a6273f983f514d6b252a3c5aba2ad)
    #2 0xee165af0aad4 in OpenImageIO::v3_1::ImageInput::read_native_scanlines(int, int, int, int, OpenImageIO::v3_1::span<std::byte, 18446744073709551615ul>) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f1aad4) (BuildId: fbc8ef25b27a6273f983f514d6b252a3c5aba2ad)
    #3 0xee165af242c4 in OpenImageIO::v3_1::ImageInput::read_scanlines(int, int, int, int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f342c4) (BuildId: fbc8ef25b27a6273f983f514d6b252a3c5aba2ad)
    #4 0xee165af1a04c in OpenImageIO::v3_1::ImageInput::read_image(int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long, long, bool (*)(void*, float), void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f2a04c) (BuildId: fbc8ef25b27a6273f983f514d6b252a3c5aba2ad)
    #5 0xee165b28b558 in OpenImageIO::v3_2_0::pvt::compute_sha1(OpenImageIO::v3_1::ImageInput*, int, int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x729b558) (BuildId: fbc8ef25b27a6273f983f514d6b252a3c5aba2ad)
    #6 0xc9c2a610ff78 in print_info_subimage(...) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x121ff78) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #7 0xc9c2a611d480 in OpenImageIO::v3_2_0::OiioTool::print_info(...) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x122d480) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #8 0xc9c2a5e6907c in input_file(...) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf7907c) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #9 0xc9c2a5ec5210 in std::_Function_handler<...>::_M_invoke(...) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xfd5210) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #10 0xee1652d79cac in OpenImageIO::v3_1::ArgParse::Impl::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb59cac) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #11 0xee1652d85260 in OpenImageIO::v3_1::ArgParse::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb65260) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #12 0xc9c2a5e8a618 in OpenImageIO::v3_2_0::OiioTool::Oiiotool::getargs(int, char**) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf9a618) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #13 0xc9c2a5b7b250 in main (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc8b250) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #14 0xee1651622598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #15 0xee1651622678 in __libc_start_main_impl ../csu/libc-start.c:360
    #16 0xc9c2a5b806ec in _start (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc906ec) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)

==235875==Register values:
 x0 = 0x0000000000000002   x1 = 0x0000000000000000   x2 = 0x0000000000000000   x3 = 0x0000000020000001
 x4 = 0x0000ffffce8f1970   x5 = 0x0000000000000001   x6 = 0x0000000000000000   x7 = 0x0000000000000000
 x8 = 0x0000000000000001   x9 = 0x00001d42c9e65a00  x10 = 0x0000ee1663697a88  x11 = 0x0000000000000000
x12 = 0x0000000000000000  x13 = 0x0000ee1663e08000  x14 = 0x000000000000015a  x15 = 0x0000000000000019
x16 = 0x0000ee16637afbf0  x17 = 0x0000ee16518c0018  x18 = 0x00001d52c9e9823c  x19 = 0x0000ea15cd62e800
x20 = 0x0000ea15cd62e800  x21 = 0x0000000000000000  x22 = 0x0000ea164f32d860  x23 = 0x0000000020000000
x24 = 0x0000001000000000  x25 = 0xffffffff80000000  x26 = 0x0000ea154d62e800  x27 = 0x0000ea164f32d000
x28 = 0x00001d52c9e65afc   fp = 0x0000ffffce8f2900   lr = 0x0000ee165b8221e4   sp = 0x0000ffffce8f1fc0
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x7832060) (BuildId: fbc8ef25b27a6273f983f514d6b252a3c5aba2ad) in dpx::ConvertToRGBInternal(dpx::Descriptor, dpx::DataSize, dpx::Characteristic, void const*, void*, int)
==235875==ABORTING
```

### Impact:
  - Immediate:  The same PoC file causes a DoS crash regardless of patch order (QueryRGBBufferSize bug or this)
  - Potential:  OOB write primitive — by choosing dimensions so that `i * 4` wraps
                to a small negative value rather than the minimum, an attacker can
                write a bounded number of bytes just before the output buffer
