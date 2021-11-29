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


## Examples

#### Realistic example: pango_font_describe

We want to get font descriptions from a gnome-shell corefile:

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

#### Parsing an int

To emulate a call to [`strtoul`](https://linux.die.net/man/3/strtoul), we have to
reserve memory for input buffer and output pointer:

```python
def parse_int(text: bytes, base=10):
    with emu.reserve(len(text)+1, align=1) as buf, emu.reserve(8) as endptr:
        buf.write_str(text)
        result = emu.call('strtoul', buf.start, endptr.start, base)
        n_parsed = endptr.read_struct('<Q')[0] - buf.start
        return result, n_parsed

parse_int(b'1841 and stuff')  # prints (1841, 4)
```

Any coredump should work with this example, unless libc is linked statically.


## Limitations

 - Right now it's tied to:

    - Linux
    - x86-64 arch
    - System V AMD64 ABI

   It wouldn't take a lot of work to make it support multiple ABIs, but well, it's work.

   It's also tied lightly to glibc, for e.g. libc patches (see below) and the RTLD debugger interface (to list symbols).

 - As indicated above, anything beyond calculations (i.e. involving the kernel) isn't supported.

   This includes threads / synchronization, memory management, I/O, etc. Some simple/essential syscalls like `mmap`, `sbrk` or even `write` may be implemented in the future.

 - Multithreading can't be emulated, and calls might fail or stall waiting for a mutex that was locked at the time of crash.

   To remediate, there's an option to patch `pthread_mutex_*` and similar calls to bypass locks. It won't magically make whatever data is protected by them consistent, but you can try.  
   In the future, we could explore things like: emulating some threads a bit until a mutex is unlocked.

 - Another inherent limitation of emulating a core file is that the emulated code may use ISA extensions that are unsupported or buggy. At the time of this writing, this has been a problem with AVX2.

   In normal emulation, the code would check the supported features first and use code paths involving supported instructions. However when emulating a core file, that autodetection has probably already been done and if your software / hardware supports these instructions, it's probable you'll hit invalid instruction errors.

   This isn't a big issue since code doesn't usually use extensions, at least not the kind of code you'd want to emulate with EmuCore. The exceptions are libc and the dynamic linker: glibc has e.g. AVX implementations for string functions. This is worked around by looking through its symbols and patching `_avx2` functions with a JMP to their `_sse2` siblings. It's reliable enough, but won't work if your libc/ld is stripped.


## Wishlist

 - Float function arguments
 - Better errors, backtraces
 - Use debug info if available (for errors, interface)
 - More archs / OSes
 - Support for `sbrk` (so that `malloc` can always work)
 - C++ support
 - Make sure it works in Python 3.8 and lower
 - Support for calling IFUNCs directly
 - Test in static binaries, Golang binaries, and non-glibc



[Unicorn]: https://www.unicorn-engine.org
[pyelftools]: https://github.com/eliben/pyelftools
