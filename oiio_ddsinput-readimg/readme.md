## CVE-2026-7582: Signed integer overflow in index arithmetic leads to out-of-bounds write in DDS image decoder

A signed 32-bit integer overflow in the DDS image decoder's pixel index calculation allows an attacker to trigger an out-of-bounds write to an attacker-controlled offset with an attacker-controlled value. The vulnerability is reachable by passing a crafted DDS file to any application that uses OpenImageIO to load images, including the project's own utilities.

- Version: 3.2.0.1-dev
- Commit: c75e31faa1bc24dea923c03a51db7be78b71c660

### Root cause:
```c
// ddsinput.cpp:963
size_t k = (z * h * w + y * w) * m_spec.nchannels;
```
All operands (z, h, w, m_spec.nchannels) are 32-bit signed int. The multiplication is evaluated entirely in 32-bit signed arithmetic before the result is widened to size_t. When the product exceeds INT_MAX, the value wraps to a large negative number. That negative int is then cast to size_t, producing a value near SIZE_MAX, and the subsequent write operation:
```c
dst[k + ch] = bit_range_convert(...);   // ddsinput.cpp:968
```
targets an address billions of bytes past the end of the allocated buffer.

### PoC (attached .dds file):
```bash
./bin/oiiotool -hash poc_dds_index_overflow.dds

# or 

./bin/iinfo -hash poc_dds_index_overflow.dds
```

### Sanitizer Output:
```bash
$ ./bin/oiiotool -hash ../poc_dds_index_overflow.dds 
/home/roo/Desktop/OpenImageIO/OpenImageIO/src/dds.imageio/ddsinput.cpp:963:48: runtime error: signed integer overflow: 536870912 * 4 cannot be represented in type 'int'
AddressSanitizer:DEADLYSIGNAL
=================================================================
==38277==ERROR: AddressSanitizer: SEGV on unknown address 0xf1f90253d800 (pc 0xf5fa906224c4 bp 0xffffce0f3eb0 sp 0xffffce0f3b80 T0)
==38277==The signal is caused by a WRITE memory access.
    #0 0xf5fa906224c4 in OpenImageIO::v3_2_0::DDSInput::internal_readimg(unsigned char*, int, int, int) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x76e24c4) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #1 0xf5fa9063bb48 in OpenImageIO::v3_2_0::DDSInput::read_native_scanline(int, int, int, int, void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x76fbb48) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #2 0xf5fa8fe22cc0 in OpenImageIO::v3_1::ImageInput::read_native_scanlines(int, int, int, int, int, void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6ee2cc0) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #3 0xf5fa8fe59b14 in OpenImageIO::v3_1::ImageInput::read_native_scanlines(int, int, int, int, OpenImageIO::v3_1::span<std::byte, 18446744073709551615ul>) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f19b14) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #4 0xf5fa8fe73304 in OpenImageIO::v3_1::ImageInput::read_scanlines(int, int, int, int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f33304) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #5 0xf5fa8fe6908c in OpenImageIO::v3_1::ImageInput::read_image(int, int, int, int, OpenImageIO::v3_1::TypeDesc, void*, long, long, long, bool (*)(void*, float), void*) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x6f2908c) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #6 0xf5fa901db598 in OpenImageIO::v3_2_0::pvt::compute_sha1(OpenImageIO::v3_1::ImageInput*, int, int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x729b598) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f)
    #7 0xaabdd1d5ff78 in print_info_subimage(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, int, int, int, OpenImageIO::v3_1::ImageSpec const&, OpenImageIO::v3_2_0::OiioTool::ImageRec*, OpenImageIO::v3_1::ImageInput*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, std::__cxx11::basic_regex<char, std::__cxx11::regex_traits<char> >&, OpenImageIO::v3_1::ImageSpec::SerialFormat, OpenImageIO::v3_1::ImageSpec::SerialVerbose) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x121ff78) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #8 0xaabdd1d6d480 in OpenImageIO::v3_2_0::OiioTool::print_info(std::ostream&, OpenImageIO::v3_2_0::OiioTool::Oiiotool&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, OpenImageIO::v3_2_0::pvt::print_info_options const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0x122d480) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #9 0xaabdd1ab907c in input_file(OpenImageIO::v3_2_0::OiioTool::Oiiotool&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>) [clone .isra.0] (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf7907c) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #10 0xaabdd1b15210 in std::_Function_handler<void (OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>), OpenImageIO::v3_1::ArgParse::Arg::action(std::function<void (OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)>&&)::{lambda(OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>)#1}>::_M_invoke(std::_Any_data const&, OpenImageIO::v3_1::ArgParse::Arg&, OpenImageIO::v3_1::span<char const* const, 18446744073709551615ul>&&) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xfd5210) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #11 0xf5fa87cc9cac in OpenImageIO::v3_1::ArgParse::Impl::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb59cac) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #12 0xf5fa87cd5260 in OpenImageIO::v3_1::ArgParse::parse_args(int, char const**) (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO_Util.so.3.2.0+0xb65260) (BuildId: 3650f1d2b564882e0c070606c1b37db90bc86625)
    #13 0xaabdd1ada618 in OpenImageIO::v3_2_0::OiioTool::Oiiotool::getargs(int, char**) (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xf9a618) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #14 0xaabdd17cb250 in main (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc8b250) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)
    #15 0xf5fa86572598 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #16 0xf5fa86572678 in __libc_start_main_impl ../csu/libc-start.c:360
    #17 0xaabdd17d06ec in _start (/home/roo/Desktop/OpenImageIO/build/bin/oiiotool+0xc906ec) (BuildId: 26dc66bb500e400fe6af08ca81c9b6cb3d954d90)

==38277==Register values:
 x0 = 0x0000000000000000   x1 = 0x0000000000000000   x2 = 0x0000f1f90253d800   x3 = 0x00000000000000bb  
 x4 = 0x00001e6750a16fd0   x5 = 0x0000f1fa83f6b830   x6 = 0x0000000000000000   x7 = 0xffffffff80000000  
 x8 = 0x0000001000000000   x9 = 0x00000000000000bb  x10 = 0x0000000000000000  x11 = 0xf2d634390b60be0a  
x12 = 0x0000000000000000  x13 = 0x0000f5fa98d4d000  x14 = 0x0000f1fa83f67a40  x15 = 0x0000000000000007  
x16 = 0x0000f5fa91d625b0  x17 = 0x0000f5fa86654400  x18 = 0x000000008001ffff  x19 = 0x0000f33a850b7e40  
x20 = 0x9ddfea08eb382d69  x21 = 0x0000f33a850b7f54  x22 = 0x0000000000000114  x23 = 0xd1c44fc794703605  
x24 = 0xffffffff80000000  x25 = 0x0000000000000000  x26 = 0x0000f1f98253d800  x27 = 0x0000f5fa86812ed8  
x28 = 0x00001e6750a16fc8   fp = 0x0000ffffce0f3eb0   lr = 0x0000f5fa906221e0   sp = 0x0000ffffce0f3b80  
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/home/roo/Desktop/OpenImageIO/build/lib/libOpenImageIO.so.3.2.0+0x76e24c4) (BuildId: d9a5db60d654cc4cee69dab2ea5033ad225a5a0f) in OpenImageIO::v3_2_0::DDSInput::internal_readimg(unsigned char*, int, int, int)
==38277==ABORTING
```

Both UBSan and ASan confirm the overflow and OOB memory write.

### Impact:
- Immediate: DoS
- Potential: Arbitrary Code Execution
