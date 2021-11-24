# EmuCore

Module that emulates function calls on a coredump.

When inspecting a coredump, it is often tedious to get the desired info by parsing your way through structures. "It would be so much easier if I could just call this function", I thought. This module attempts to make that possible, within certain [limitations](#limitations).

Disclaimer: This is more of a proof of concept right now and I don't anticipate having time to improve or maintain this. You've been warned.

Features:
 - Simple API
 - Collects symbols
 - Automatically loads mapped files
 - Supports inspecting on different machine
 - Independent of host*
 - Debug info isn't required

(*) Page size should be the same.

Dependencies:
 - [Unicorn][] to emulate the CPU
 - [pyelftools][] to parse coredump and symbols


## Usage

```python
from emucore import EmuCore

# opens core file, opens referenced files,
# initializes emulator (takes a while)
emu = EmuCore("/tmp/core.3007")

def get_font_description(font_addr: int) -> str:
    desc = emu.call('pango_font_describe', font_addr)
    dstr = emu.call('pango_font_description_to_string', desc)
    return emu.mem(dstr).read_str()

print(f'Font name: {get_font_description(0x555a4626b4e0)}')
```

If we were to use `get_font_description` a lot of times, we should also free the memory afterwards.


## Limitations

 - Right now it's tied to:

    - Linux
    - x86-64 arch
    - System V AMD64 ABI

   It wouldn't take a lot of work to make it support multiple ABIs, but well, it's work.

   It's also tied lightly to glibc, for e.g. libc patches (see below) and the RTLD debugger interface (to list symbols).

 - As indicated above, anything beyond calculations (i.e. involving the kernel) isn't supported.

   This includes threads / synchronization, memory management, I/O, etc. Some simple/essential syscalls like `mmap`, `sbrk` or even `write` may be implemented in the future.

 - Another inherent limitation of emulating a core file is that QEMU (the base for Unicorn) cannot emulate certain instruction sets like AVX2.
 
   In normal emulation, the code would check the supported features first and use code paths involving supported instructions. However when emulating a core file, that autodetection has probably already been done and if your software / hardware supports this instructions, it's probable you'll hit invalid instruction errors.

   This isn't a big issue since code doesn't usually use these extensions, at least not the kind of code you'd want to emulate with EmuCore. The exception is libc: glibc has AVX2 implementations for string functions. This is worked around by looking through its symbols and patching `_avx2` functions with a JMP to their `_sse2` siblings. It's reliable enough, but won't work if your libc is stripped.


## Wishlist

 - Better errors, backtraces
 - Use debug info if available (for errors, interface)
 - More archs / OSes
 - Support for `sbrk` (so that `malloc` can always work)
 - C++ support
 - Configurable logging
 - Make sure it works in Python 3.8 and lower



[Unicorn]: https://www.unicorn-engine.org
[pyelftools]: https://github.com/eliben/pyelftools
