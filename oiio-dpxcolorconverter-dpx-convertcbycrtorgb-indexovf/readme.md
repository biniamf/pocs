## Signed integer overflow in ConvertCbYCrYToRGB leads to heap out-of-bounds write in DPX 4:2:2 decoder

A signed 32-bit integer overflow in the pixel-loop index expression `i * 3` inside ConvertCbYCrYToRGB() causes the function to compute a large negative pointer offset into the output buffer, producing an out-of-bounds write that crashes the process. 

- Version: 3.2.0.1-dev
- Commit:  c75e31faa1bc24dea923c03a51db7be78b71c660


Root cause (DPXColorConverter.cpp:144-153):
  ```c
  // 4:2:2
  template <typename DATA, unsigned int max>
  static bool ConvertCbYCrYToRGB(const Characteristic space,
      const DATA *input, DATA *output, const int pixels) {
      const float *matrix = GetYCbCrToRGBColorMatrix(space);
      if (matrix == NULL)
          return false;
      DATA CbYCr[3];
      for (int i = 0; i < pixels; i++) {
          CbYCr[0] = input[(i | 1) * 2];   // Cb
          CbYCr[1] = input[i * 2 + 1];     // Y
          CbYCr[2] = input[(i & ~1) * 2];  // Cr
          ConvertPixelYCbCrToRGB<DATA, max>(CbYCr, &output[i * 3], matrix);
          //                                              ^^^^^^^^
          //   signed 32-bit overflow when i = 715,827,883:
          //   715,827,883 * 3 = 2,147,483,649  (> INT_MAX)
          //   as int32          = -2,147,483,647
          //   &output[-2,147,483,647]  →  OOB write → SEGV
      }
      return true;
  }
  ```
`pixels` is declared as `int` and is computed from the image block dimensions (Width * Height).  When the product exceeds INT_MAX/3, the multiply `i * 3` overflows on the final iteration, producing a large negative pointer offset.

### Proof-of-concept

PoC (attached file): poc_dpx_cbycry_indexovf.dpx - crafted DPX file (~1.43 GB sparse)

### Run:
  ```bash
  ./bin/oiiotool --hash poc_dpx_cbycry_indexovf.dpx
  # or
  ./bin/iinfo   --hash poc_dpx_cbycry_indexovf.dpx
  ```


<details>
<summary>Sanitizer output</summary>

```bash
$ ./bin/oiiotool --hash poc_dpx_cbycry_indexovf.dpx 2>&1

/home/roo/Desktop/OpenImageIO/OpenImageIO/src/dpx.imageio/libdpx/DPXColorConverter.cpp:294:25: runtime error: signed integer overflow: 715827884 * 3 cannot be represented in type 'int'
/home/roo/Desktop/OpenImageIO/OpenImageIO/src/dpx.imageio/libdpx/DPXColorConverter.cpp:151:55: runtime error: signed integer overflow: 715827883 * 3 cannot be represented in type 'int'
AddressSanitizer:DEADLYSIGNAL
=================================================================
==49144==ERROR: AddressSanitizer: SEGV on unknown address 0xe0dc0a61e803 (pc 0xe4dd18812c04 bp 0xfffffcccc550 sp 0xfffffcccbc10 T0)
==49144==The signal is caused by a WRITE memory access.
    #0 0xe4dd18812c04 in dpx::ConvertToRGBInternal(dpx::Descriptor, dpx::DataSize, dpx::Characteristic, void const*, void*, int) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x7832c04) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #1 0xe4dd1871dc54 in OpenImageIO::v3_2_0::DPXInput::read_native_scanlines(int, int, int, int, int, void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x773dc54) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #2 0xe4dd17ef9b14 in OpenImageIO::v3_1::ImageInput::read_native_scanlines(int, int, int, int, OpenImageIO::v3_1::span<std::byte, 18446744073709551615ul>) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f19b14) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #3 0xe4dd17f13304 in OpenImageIO::v3_1::ImageInput::read_scanlines(int, int, int, int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f33304) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #4 0xe4dd17f0908c in OpenImageIO::v3_1::ImageInput::read_image(int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long, long, bool (*)(void*, float), void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f2908c) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #5 0xe4dd1827b598 in OpenImageIO::v3_2_0::pvt::compute_sha1(OpenImageIO::v3_1::ImageInput*, int, int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x729b598) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #6 0xb612a047ff78 in print_info_subimage(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, int, int, int, OpenImageIO::v3_1::ImageSpec const&, OpenImageIO::v3_2_0::OiioTool::ImageRec*, OpenImageIO::v3_1::ImageInput*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, OpenImageIO::v3_1::ImageSpec::SerialFormat, OpenImageIO::v3_1::ImageSpec::SerialVerbose) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x121ff78) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #7 0xb612a048d480 in OpenImageIO::v3_2_0::OiioTool::print_info(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x122d480) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #8 0xb612a01d907c in input_file(OpenImageIO::v3_2_0::OiioTool::Oiiotool&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>) [clone .isra.0] (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf7907c) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #9 0xb612a0235210 in std::_Function_handler<void (OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>), OpenImageIO::v3_1::ArgParse::Arg::action(std::function<void (OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)>&&)::{lambda(OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)#1}>::_M_invoke(std::_Any_data const&, OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>&&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xfd5210) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #10 0xe4dd0fd69cac in OpenImageIO::v3_1::ArgParse::Impl::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb59cac) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #11 0xe4dd0fd75260 in OpenImageIO::v3_1::ArgParse::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb65260) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #12 0xb612a01fa618 in OpenImageIO::v3_2_0::OiioTool::Oiiotool::getargs(int, char**) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf9a618) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #13 0xb6129feeb250 in main (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc8b250) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #14 0xe4dd0e612598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #15 0xe4dd0e612678 in __libc_start_main_impl ../csu/libc-start.c:360
    #16 0xb6129fef06ec in _start (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc906ec) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)

==49144==Register values:
 x0 = 0x00001c1ba1866c08   x1 = 0x0000000000000000   x2 = 0x00001c1ba1866c06   x3 = 0x0000001000000000  
 x4 = 0x0000e0dc8a61e800   x5 = 0x00001c1ba1866c20   x6 = 0x0000e4dd199fa2d4   x7 = 0x0000e4dd199fa2c4  
 x8 = 0x0000e4dd199fa2cc   x9 = 0xffffffff80000001  x10 = 0x0000e4dd199fa2dc  x11 = 0x0000e4dd199fa2e0  
x12 = 0x000000002aaaaaac  x13 = 0x0000e0dd0c3367f2  x14 = 0x0000e0dd0c3367f1  x15 = 0x000000002aaaaaab  
x16 = 0x0000000000000004  x17 = 0x0000e4dd2079fbf0  x18 = 0x0000e0dd0c3367f0  x19 = 0x0000e0dc8a61e800  
x20 = 0x0000e0dd0c335860  x21 = 0x0000e0dd0c336860  x22 = 0x0000e4dd199fa2c0  x23 = 0x0000e0dd0c332860  
x24 = 0x0000e0dd0c336100  x25 = 0x0000e0dc0a61e801  x26 = 0x0000e0dd0c336030  x27 = 0x0000e0dd0c3360f0  
x28 = 0x0000e0dd0c336040   fp = 0x0000fffffcccc550   lr = 0x0000e4dd18821230   sp = 0x0000fffffcccbc10  
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x7832c04) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f) in dpx::ConvertToRGBInternal(dpx::Descriptor, dpx::DataSize, dpx::Characteristic, void const*, void*, int)
==49144==ABORTING
```

</details>



Impact:
  - Immediate:  DoS — process crashes unconditionally after processing 715 M pixels
  - Potential:  OOB write primitive — an attacker can write a bounded number of bytes just before the output buffer in heap memory
