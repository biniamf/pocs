## Integer overflow in QueryRGBBufferSizeInternal leads to heap out-of-bounds write in DPX decoder (kCbYCr and kABGR)

A signed 32-bit integer overflow in QueryRGBBufferSizeInternal() affects two separate case branches, producing heap out-of-bounds writes via different descriptors:

  - Case 1 (kCbYCr, line 298):  `pixels * -3 * bytes` — wraps to +1 for large pixels
    - -> m_decodebuf.resize(1); fread writes 15 bytes → 14-byte OOB write

  - Case 2 (kABGR, line 306):   `pixels * -4 * bytes` — wraps to +2,147,483,644
    - -> m_decodebuf.resize(2,147,483,644); fread writes 2,147,483,652 bytes -> 8-byte OOB write

Both cases share the same root cause (signed overflow in the same function). Two PoC files are attached, one for each affected descriptor.

- Version: 3.2.0.1-dev
- Commit:  c75e31faa1bc24dea923c03a51db7be78b71c660

Root cause (DPXColorConverter.cpp):

```c
static inline int QueryRGBBufferSizeInternal(
    const Descriptor desc, const int pixels, const int bytes) {
    ...
    case kCbYCr:              // line 298 — 4:4:4 YCbCr
        return pixels * -3 * bytes;
    ...
    case kCbYCrA:
    case kRGBA:
    case kABGR:               // line 306 — ABGR / 4:4:4:4 YCbCrA
        return pixels * -4 * bytes;
}
```

All arithmetic is 32-bit signed int. A negative return value is the intended signal that no separate buffer is needed (in-place conversion). For large pixel counts the true result is more negative than INT_MIN, wrapping to a small positive number.
dpxinput.cpp:603 checks `if (bufsize > 0)` and allocates m_decodebuf with that incorrect size. ReadDirect then writes the full imageByteSize into the undersized buffer leading to heap out-of-bounds write.

### Case 1: kCbYCr (line 298) 
PoC file: poc_dpx_cbycr_oob.dpx

Run:
```bash
  ./bin/oiiotool --hash poc_dpx_cbycr_oob.dpx 
```
Or
```bash  
  ./bin/iinfo   --hash poc_dpx_cbycr_oob.dpx
```

### Case 1: kABGR (line 306)
PoC file: poc_dpx_abgr_oob.dpx, (~2.1 GB sparse)


### Run:

```bash  
  ./bin/oiiotool --hash poc_dpx_abgr_oob.dpx
```
Or
```bash  
  ./bin/iinfo   --hash poc_dpx_abgr_oob.dpx
```

<details>
<summary>Sanitizer Output — Case 1 (kCbYCr)</summary>

```bash
 $ ./bin/oiiotool --hash ../poc_dpx_cbycr_oob.dpx
/home/roo/Desktop/OpenImageIO/OpenImageIO/src/dpx.imageio/libdpx/DPXColorConverter.cpp:298:26: runtime error: signed integer overflow: 1431655765 * -3 cannot be represented in type 'int'
=================================================================
==47723==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdc3fbaa0f851 at pc 0xe01fcdf2f4cc bp 0xfffffb1e5b50 sp 0xfffffb1e5330
WRITE of size 15 at 0xdc3fbaa0f851 thread T0
    #0 0xe01fcdf2f4c8 in fread ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:1030
    #1 0xe01fbd6b3f90 in OpenImageIO::v3_1::Filesystem::IOFile::read(void*, unsigned long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xc73f90) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #2 0xe01fc5ff4c90 in dpx::Reader::ReadBlock(int, unsigned char*, dpx::Block&) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x77e4c90) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #3 0xe01fc5f4dc20 in OpenImageIO::v3_2_0::DPXInput::read_native_scanlines(int, int, int, int, int, void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x773dc20) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #4 0xe01fc5729b14 in OpenImageIO::v3_1::ImageInput::read_native_scanlines(int, int, int, int, OpenImageIO::v3_1::span<std::byte, 18446744073709551615ul>) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f19b14) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #5 0xe01fc5743304 in OpenImageIO::v3_1::ImageInput::read_scanlines(int, int, int, int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f33304) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #6 0xe01fc573908c in OpenImageIO::v3_1::ImageInput::read_image(int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long, long, bool (*)(void*, float), void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f2908c) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #7 0xe01fc5aab598 in OpenImageIO::v3_2_0::pvt::compute_sha1(OpenImageIO::v3_1::ImageInput*, int, int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x729b598) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #8 0xb0b6e66aff78 in print_info_subimage(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, int, int, int, OpenImageIO::v3_1::ImageSpec const&, OpenImageIO::v3_2_0::OiioTool::ImageRec*, OpenImageIO::v3_1::ImageInput*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, OpenImageIO::v3_1::ImageSpec::SerialFormat, OpenImageIO::v3_1::ImageSpec::SerialVerbose) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x121ff78) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #9 0xb0b6e66bd480 in OpenImageIO::v3_2_0::OiioTool::print_info(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x122d480) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #10 0xb0b6e640907c in input_file(OpenImageIO::v3_2_0::OiioTool::Oiiotool&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>) [clone .isra.0] (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf7907c) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #11 0xb0b6e6465210 in std::_Function_handler<void (OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>), OpenImageIO::v3_1::ArgParse::Arg::action(std::function<void (OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)>&&)::{lambda(OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)#1}>::_M_invoke(std::_Any_data const&, OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>&&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xfd5210) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #12 0xe01fbd599cac in OpenImageIO::v3_1::ArgParse::Impl::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb59cac) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #13 0xe01fbd5a5260 in OpenImageIO::v3_1::ArgParse::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb65260) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #14 0xb0b6e642a618 in OpenImageIO::v3_2_0::OiioTool::Oiiotool::getargs(int, char**) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf9a618) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #15 0xb0b6e611b250 in main (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc8b250) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #16 0xe01fbbe42598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #17 0xe01fbbe42678 in __libc_start_main_impl ../csu/libc-start.c:360
    #18 0xb0b6e61206ec in _start (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc906ec) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)

0xdc3fbaa0f851 is located 0 bytes after 1-byte region [0xdc3fbaa0f850,0xdc3fbaa0f851)
allocated by thread T0 here:
    #0 0xe01fcdfab17c in operator new(unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:86
    #1 0xe01fc58af6b4 in std::vector<unsigned char, std::allocator<unsigned char> >::_M_default_append(unsigned long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x709f6b4) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #2 0xe01fc5f4db78 in OpenImageIO::v3_2_0::DPXInput::read_native_scanlines(int, int, int, int, int, void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x773db78) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #3 0xe01fc5729b14 in OpenImageIO::v3_1::ImageInput::read_native_scanlines(int, int, int, int, OpenImageIO::v3_1::span<std::byte, 18446744073709551615ul>) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f19b14) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #4 0xe01fc5743304 in OpenImageIO::v3_1::ImageInput::read_scanlines(int, int, int, int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f33304) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #5 0xe01fc573908c in OpenImageIO::v3_1::ImageInput::read_image(int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long, long, bool (*)(void*, float), void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f2908c) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #6 0xe01fc5aab598 in OpenImageIO::v3_2_0::pvt::compute_sha1(OpenImageIO::v3_1::ImageInput*, int, int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x729b598) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #7 0xb0b6e66aff78 in print_info_subimage(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, int, int, int, OpenImageIO::v3_1::ImageSpec const&, OpenImageIO::v3_2_0::OiioTool::ImageRec*, OpenImageIO::v3_1::ImageInput*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, OpenImageIO::v3_1::ImageSpec::SerialFormat, OpenImageIO::v3_1::ImageSpec::SerialVerbose) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x121ff78) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #8 0xb0b6e66bd480 in OpenImageIO::v3_2_0::OiioTool::print_info(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x122d480) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #9 0xb0b6e640907c in input_file(OpenImageIO::v3_2_0::OiioTool::Oiiotool&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>) [clone .isra.0] (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf7907c) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #10 0xb0b6e6465210 in std::_Function_handler<void (OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>), OpenImageIO::v3_1::ArgParse::Arg::action(std::function<void (OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)>&&)::{lambda(OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)#1}>::_M_invoke(std::_Any_data const&, OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>&&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xfd5210) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #11 0xe01fbd599cac in OpenImageIO::v3_1::ArgParse::Impl::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb59cac) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #12 0xe01fbd5a5260 in OpenImageIO::v3_1::ArgParse::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb65260) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #13 0xb0b6e642a618 in OpenImageIO::v3_2_0::OiioTool::Oiiotool::getargs(int, char**) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf9a618) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #14 0xb0b6e611b250 in main (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc8b250) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #15 0xe01fbbe42598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #16 0xe01fbbe42678 in __libc_start_main_impl ../csu/libc-start.c:360
    #17 0xb0b6e61206ec in _start (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc906ec) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xc73f90) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625) in OpenImageIO::v3_1::Filesystem::IOFile::read(void*, unsigned long)
Shadow bytes around the buggy address:
  0xdc3fbaa0f580: fa fa fd fa fa fa 00 fa fa fa 00 fa fa fa fd fa
  0xdc3fbaa0f600: fa fa 00 fa fa fa 00 fa fa fa fd fa fa fa fd fa
  0xdc3fbaa0f680: fa fa fd fa fa fa 00 fa fa fa 00 00 fa fa 00 00
  0xdc3fbaa0f700: fa fa 00 00 fa fa fd fa fa fa 00 00 fa fa 00 00
  0xdc3fbaa0f780: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
=>0xdc3fbaa0f800: fa fa 04 fa fa fa fd fd fa fa[01]fa fa fa fa fa
  0xdc3fbaa0f880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xdc3fbaa0f900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xdc3fbaa0f980: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xdc3fbaa0fa00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xdc3fbaa0fa80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==47723==ABORTING
```

</details>


<details>
<summary>Sanitizer Output — Case 2 (kABGR)</summary>

```bash
 $ ./bin/oiiotool --hash ../poc_dpx_abgr_oob.dpx
/home/roo/Desktop/OpenImageIO/OpenImageIO/src/dpx.imageio/libdpx/DPXColorConverter.cpp:306:26: runtime error: signed integer overflow: 536870913 * -4 cannot be represented in type 'int'
==100095==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xf7c4aac0c7fc
WRITE of size 2147483652 at 0xf7c4aac0c7fc thread T0
    #0  fread
    #1  OpenImageIO::v3_1::Filesystem::IOFile::read(void*, unsigned long)
    #2  dpx::Reader::ReadBlock(int, unsigned char*, dpx::Block&)
    #3  OpenImageIO::v3_2_0::DPXInput::read_native_scanlines(...)
    #4  OpenImageIO::v3_1::ImageInput::read_native_scanlines(...)
    #5  OpenImageIO::v3_1::ImageInput::read_scanlines(...)
    #6  OpenImageIO::v3_1::ImageInput::read_image(...)
    #7  OpenImageIO::v3_2_0::pvt::compute_sha1(...)
    #8  print_info_subimage(...)  [oiiotool]
    ...
    #14 main  [oiiotool]

0xf7c4aac0c7fc is located 0 bytes after 2147483644-byte region
  allocated by DPXInput::read_native_scanlines → m_decodebuf.resize(bufsize)

SUMMARY: AddressSanitizer: heap-buffer-overflow in IOFile::read(void*, unsigned long)
```
</details>


### Impact:

- Immediate:  DoS — process crashes unconditionally on opening a crafted DPX file
              via any code path that reads pixel data (oiiotool, iinfo, any library
              consumer calling read_image or read_scanlines)
- Potential:  Heap corruption — fread writes attacker-controlled pixel bytes into adjacent heap memory
