"""
Main module, exposes public API
"""

from inspect import signature
import logging
import re
from collections import defaultdict
import ctypes
from io import DEFAULT_BUFFER_SIZE, BufferedRandom, BytesIO
import os
from typing import Callable, Literal, Optional, Union
from unicorn.unicorn import Uc, UcContext, UcError, uc, x86_const
from elftools.elf import elffile, sections
import mmap
import struct
import bisect
from contextlib import contextmanager

from .utils import \
    UnicornIO, read_struct, write_struct, read_bstr, read_str, write_str, \
    sort_and_ensure_disjoint, VMA, \
    parse_load_segments, parse_file_note, Prstatus, FileMapping, \
    parse_auxv_note, AuxvField, \
    parse_program_header, parse_dynamic_section, RtState, RtLoadedObject, Symbol, \
    mmapsize, elf_flags_to_uc_prot, SYSV_AMD_ARG_REGS, UC_MEM_TYPES

from .syscall import SyscallX64, Errno, FutexCmd, FutexOp

__all__ = ['EmuCore', 'EmulationError']

logger = logging.getLogger(__name__)

# try to load stack tracing module
tracer_exc = None
try:
    from .tracer.binding import StackTracer
except ImportError as e:
    tracer_exc = e
tracer_exc_logged = False
def is_stack_tracer_available():
    global tracer_exc_logged
    if not (tracer_exc is None) and not tracer_exc_logged:
        logger.warn('stack tracing requested but not available, disabling...', exc_info=tracer_exc)
        tracer_exc_logged = True
    return tracer_exc is None

# FIXME: a lot of these asserts should be exceptions, we should have a class
# FIXME: proper log system

# FIXME: in the memory mapping phase, the code assumes that our
# PAGESIZE is the same as the core dump's:
#  - if ours is higher: mmapping will fail if given an unaligned offset
#  - if core dump's is higher: last-page rounding will not match up with the VMA rounding
# Also, Unicorn engine page size must not be higher, checked below

# minimum access required by Unicorn on mapped areas, otherwise behaviour is undefined
REQUIRED_PROT = mmap.PROT_READ | mmap.PROT_WRITE

class EmulationError(Exception):
    pass

class EmuCore(object):
    '''Emulator for core dumps.

    Once an instance is constructed and ready for use, see `call()` to invoke
    functions. `call()` is low-level and accepts integer arguments (which may
    be pointers) and returns the result as an integer.
    
    Use `mem()` to read or write memory of the emulator, and use `reserve()`
    if you need to allocate some space on the stack. Both return a raw I/O
    instance with some convenience methods injected into it, such as
    `read_str()`, `read_bstr()`, `read_struct()` and its `write_` equivalents;
    these are not present in the typings, see the `emucore.utils` module.

    The corefile comes with metadata about the memory mappings and state
    of the process / threads at the time of dump. Properties like `mappings`,
    `auxv`, `threads`, make that info available. There's also the `find_mapping()`
    function to query the mapping that an address falls into.

    EmuCore also attempts to load info about the loaded objects and its symbols.
    This info is available in the `loaded_objects` and `symbols` properties,
    but it's easier to use `get_symbol()` / `get_symbols()` to query a symbol
    by its name. To attempt to find the symbol that an address falls into, use
    `find_symbol()` instead.

    For advanced use cases, the Unicorn instance can be accessed through the
    `emu` property. `emu_ctx` holds a Unicorn context that is restored at the
    start of each `call()` invocation.
    '''

    # open resources (FIXME: make this class a context manager)
    emu: Uc
    stack_tracer: 'StackTracer'
    core: elffile.ELFFile
    core_mm: mmap.mmap
    mappings_mm: dict[bytes, tuple[bytes, mmap.mmap]]

    # parsed info
    threads: list[Prstatus]
    mappings: list[FileMapping]
    mappings__keys: list[int]    # start addresses
    auxv: dict[int, int]
    # WARNING: below properties will be absent if __load_symbols() failed
    loaded_objects: list[RtLoadedObject]
    symbols: dict[str, set[Symbol]]
    symbols_by_type_by_addr: dict[
        Symbol.Type,             # for each type...
        tuple[
            list[int],           # keys (addresses)
            list[set[Symbol]],  # values (symbols at an address)
        ]
    ]

    emu_ctx: UcContext

    # stack management
    stack_base: int
    stack_size: int
    stack_addr: int

    def __init__(
        self, filename: str,
        patch_glibc: bool=True, patch_lock: bool=False, mapping_load_kwargs={},
        stack_addr: int = 0x7f10000000000000, stack_size: int = 16 * 1024 * 1024,
        trace_stack: bool = True,
    ):
        '''Parses the corefile, loads the referenced files, and initializes a
        Unicorn emulator instance mapped with its memory.

        This takes a while, enable INFO log messages to see progress.

        Parameters:

          - `filename`: location of corefile to load

          - `mapping_load_kwargs`: parameters passed to `__load_mappings()` that
            influence how and which files referenced by the corefile (such as
            shared libraries) are loaded. see `__load_mappings()`.

          - `patch_glibc`: attempt to patch glibc codepaths that use SIMD instructions
            we don't have, to prevent invalid instruction errors (default: True)

          - `patch_lock`: patch common pthread calls to lock / unlock mutexes so that
            they always succeed rather than fail, loop or syscall. it won't magically
            make the data protected by them consistent, but can work (default: False)

          - `stack_addr`, `stack_size`: location and size of our custom stack area,
            used by `call()` and `reserve()` to emulate calls. By default a 16MiB
            stack is used, in some cases you may need a bigger size.
        
          - `trace_stack`: trace stack pointer at basic block boundary to be able to
            reconstruct a sort of call stack (default: True, you may want to disable it
            for performance)
        '''
        # Start by opening the core file
        self.core = elffile.ELFFile(open(filename, 'rb'))
        assert self.core['e_ident']['EI_OSABI'] in {'ELFOSABI_SYSV', 'ELFOSABI_LINUX'}, \
            'only Linux supported'
        assert self.core['e_machine'] == 'EM_X86_64', 'only x86-64 supported'
        assert self.core['e_type'] == 'ET_CORE', 'not a core file'

        # Parse coredump notes
        segs = self.core.iter_segments()
        note_segs = filter(lambda seg: isinstance(seg, elffile.NoteSegment), segs)
        notes = [ n for seg in note_segs for n in seg.iter_notes() ]
        # files
        file_note = next(n['n_desc'] for n in notes if n['n_type'] == 'NT_FILE')
        self.mappings = sort_and_ensure_disjoint(
            parse_file_note(file_note), lambda x: x[1])
        self.mappings__keys = [ vma.start for _, vma in self.mappings ]
        # threads
        self.threads = list(map(Prstatus.load,
            filter(lambda n: n['n_type'] == 'NT_PRSTATUS', notes)))
        # process
        # FIXME: parse PRPSINFO
        self.auxv = parse_auxv_note(
            next( n for n in notes if n['n_type'] == 'NT_AUXV' ))

        # Initialize emulator instance
        self.emu = Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
        # restore FS and GS from a random thread (userspace typically
        # stores TCB in FS, any TLS-related stuff will fail if not initialized)
        for reg in {x86_const.UC_X86_REG_FS_BASE, x86_const.UC_X86_REG_GS_BASE}:
            self.emu.reg_write(reg, self.threads[0].regs[reg])
        # save clean context
        self.emu_ctx = self.emu.context_save()
        # register hooks
        hooks = [
            (uc.UC_HOOK_MEM_INVALID, self.__hook_mem),
            (uc.UC_HOOK_INSN_INVALID, self.__hook_insn_invalid),
            (uc.UC_HOOK_INTR, self.__hook_intr),
            (uc.UC_HOOK_INSN, lambda: self.__hook_intr('syscall'), x86_const.UC_X86_INS_SYSCALL),
            (uc.UC_HOOK_INSN, lambda: self.__hook_intr('sysenter'), x86_const.UC_X86_INS_SYSENTER),
        ]
        for hook, cb, *args in hooks:
            self.emu.hook_add(hook, (lambda cb: lambda *args: cb(*args[1:-1]))(cb), None, 1, 0, *args)
        # setup stack tracer
        self.stack_tracer = None
        if trace_stack and is_stack_tracer_available():
            self.stack_tracer = StackTracer(256)
            self.stack_tracer.set_attached(True, self.emu)

        # Map everything into emulator
        if (pagesize := self.auxv[AuxvField.PAGESZ.value]) != mmap.PAGESIZE:
            logger.warn(f'coredump page size ({pagesize}) differs from host ({mmap.PAGESIZE})')
        assert self.emu.query(uc.UC_QUERY_PAGE_SIZE) <= mmap.PAGESIZE
        # (first core segments, then RO mappings over any uncovered areas)
        self.__load_core_segments()
        self.__load_mappings(**mapping_load_kwargs)

        # Load symbols from binary and loaded objects
        logger.info('Loading symbols...')
        self.__load_symbols()

        # Post-load fixups
        logger.info('Performing fixups...')
        if patch_glibc: self.__patch_glibc()
        if patch_lock: self.__patch_pthreads()

        # Map our stack area
        self.stack_addr, self.stack_size = stack_addr, stack_size
        self.stack_base = stack_addr - stack_size
        self.emu.mem_map(self.stack_base, self.stack_size, uc.UC_PROT_ALL)

    # MEMORY MAPPING

    def __load_core_segments(self):
        '''Read LOAD segments from core and map them'''
        load_segs = parse_load_segments(self.core)
        logger.info(f'Mapping {len(load_segs)} LOAD segments...')
        corefd = self.core.stream.fileno()
        self.core_mm = mm = mmap.mmap(corefd, 0, mmap.MAP_PRIVATE, REQUIRED_PROT)
        for vma, flags in load_segs:
            prot = elf_flags_to_uc_prot(flags)
            assert vma.offset_end <= mmapsize(mm), 'segment exceeds file, malformed ELF'
            ptr = ctypes.byref((ctypes.c_char*1).from_buffer(mm, vma.offset))
            self.emu.mem_map_ptr(vma.start, vma.size, prot, ptr)

    def __load_mappings(self,
        whitelist: list[Union[str, bytes]]=[],
        blacklist: list[Union[str, bytes]]=['/dev/', '/proc/', '/sys/'],
        skip_invalid: bool=True, skip_special: bool=True,
        filename_map: Callable[[bytes], Optional[Union[str, bytes]]] = lambda x: x,
    ):
        '''Read VMAs from core and map the associated files from disk

        Parameters to filter which files to map:
        - skip_special: Skip files whose mapped filename (see below) is found
        on disk, but is not a regular file (devices, directories, etc.) (default is True)
        - skip_invalid: Skip files we can't access, such as deleted
        files and anonymous mappings (default is True)
        - blacklist: List of prefixes to never map (default: /dev/, /proc/, /sys/)
        - whitelist: List of prefixes to always map (default empty, has most priority)

        After filtering as instructed above, a `filename_map` can optionally be provided
        to transform mapped filenames. The function will be called with the original
        filename and must return the filename to access on disk, or None to skip the file.
        '''
        ensure_bytes = lambda x: x.encode() if isinstance(x, str) else x
        blacklist = list(map(ensure_bytes, blacklist))
        whitelist = list(map(ensure_bytes, whitelist))
        filename_map = (lambda o: lambda fn: ensure_bytes(o(fn)))(filename_map)

        # remove mappings that overlap with already loaded regions
        regions = sort_and_ensure_disjoint((s, e+1) for s, e, _ in self.emu.mem_regions())
        mappings = []
        for fname, (start, end, offset) in self.mappings:
            while True:
                regstart, regend = regions[0] if regions else (end, end)
                if regend > start:
                    if start < regstart:
                        mappings.append((fname, VMA(start, min(end, regstart), offset)))
                    if end <= regend: break
                    start, offset = regend, offset + (regend - start)
                regions.pop(0)

        # collect simplified mappings for each file
        # (note that we keep all files, even if they no longer have VMAs)
        file_mappings: dict[bytes, list[VMA]] = { fn: [] for fn, _ in self.mappings }
        for fname, vma in mappings:
            file_mappings[fname].append(vma)
        file_mappings = { k: VMA.simplify(v) for k, v in file_mappings.items() }

        # filter / transform files according to settings
        is_invalid = lambda fn: \
            fn.startswith(b'anon_inode:') or fn.startswith(b'/memfd:') or fn.endswith(b' (deleted)')
        is_special = lambda fn: \
            (fn := filename_map(fn)) != None and os.path.exists(fn) and not os.path.isfile(fn)
        file_skipped = lambda fn: \
            (skip_invalid and is_invalid(fn)) or (skip_special and is_special(fn)) \
            or any(fn.startswith(pref) for pref in blacklist)
        file_filter = lambda fn: \
            any(fn.startswith(pref) for pref in whitelist) or not file_skipped(fn)
        mapped_filenames = { fn: fn2 for fn in file_mappings
            if file_filter(fn) and (fn2 := filename_map(fn)) != None }

        skipped_with_vmas = [ fn for fn, vmas in file_mappings.items()
            if fn not in mapped_filenames and vmas ]
        if skipped_with_vmas:
            logger.info('Skipped files with VMAs:\n{}'.format('\n'.join(
                f' - {fn.decode(errors="replace")}' for fn in skipped_with_vmas )))
        file_mappings = { fn: v for fn, v in file_mappings.items() if fn in mapped_filenames }
        total_mappings = sum(len(v) for v in file_mappings.values())
        logger.info(f'Mapping {len(file_mappings)} files, {total_mappings} VMAs...')

        # map files (FIXME: catch open() errors and move on)
        self.mappings_mm = {}
        for fn, vmas in file_mappings.items():
            with open(mapped_filenames[fn], 'rb') as f:
                mm = mmap.mmap(f.fileno(), 0, mmap.MAP_PRIVATE, REQUIRED_PROT)
                self.mappings_mm[fn] = (mapped_filenames[fn], mm)
            for vma in vmas:
                # we know it's not writeable (otherwise it would be in the coredump)
                # so make it RX (FIXME look into sections?)
                prot = uc.UC_PROT_READ | uc.UC_PROT_EXEC
                assert vma.offset_end <= mmapsize(mm), \
                    f'invalid mapping on {fn}: {vma}'
                ptr = ctypes.byref((ctypes.c_char*1).from_buffer(mm, vma.offset))
                self.emu.mem_map_ptr(vma.start, vma.size, prot, ptr)

    def mem(self, start: Union[int, str]=0, size: Optional[int]=None, offset: int=0, buffer_size: int=DEFAULT_BUFFER_SIZE):
        '''Returns a binary I/O stream over (a region of) memory

        First two arguments restrict the accessible memory range,
        with `start` being exposed at offset 0.

        The `offset` parameter calls seek() on the returned stream.

        If `start` is a string, it will be resolved as an `OBJECT` symbol
        and `size` will default to the symbol size (if defined).
        If you need more control, call `get_symbol()` directly.
        '''
        if isinstance(start, str):
            if not (syms := self.get_symbols(start, stype=Symbol.Type.OBJECT)):
                raise ValueError(f'no OBJECT symbol found for {start}')
            start, size = syms[0].addr, syms[0].size
        stream = UnicornIO(self.emu, start, size, offset)
        # FIXME: BufferedRandom fails with some obscure exception from native code...
        #stream = BufferedRandom(stream, buffer_size) if buffer_size > 0 else stream
        # inject convenience methods (FIXME: more elegant way?)
        stream.read_struct = lambda *args, **kwargs: read_struct(stream, *args, **kwargs)
        stream.write_struct = lambda *args, **kwargs: write_struct(stream, *args, **kwargs)
        stream.read_bstr = lambda *args, **kwargs: read_bstr(stream, *args, **kwargs)
        stream.read_str = lambda *args, **kwargs: read_str(stream, *args, **kwargs)
        stream.write_str = lambda *args, **kwargs: write_str(stream, *args, **kwargs)
        return stream

    @contextmanager
    def reserve(self, size: int, align=8):
        '''Returns a context manager object that allocates memory on our stack area.

        The `align` parameter (default: 8) skips memory before the allocation so
        that its *start* ends up aligned to it.

        Note that these allocations take space from the stack area, i.e.
        functions will have less available space to run. For big allocations
        you may even run out of space in the stack yourself; the area can be
        enlarged through the `stack_size` parameter in the constructor.

        If you don't use the `with` statement, make sure that reservations
        are released in REVERSE ORDER, anything else will raise.

        The address of the allocated area can be get through the `start` attribute.
        '''
        if not size:
            return self.mem(self.stack_addr, 0)
        old_stack_addr = self.stack_addr
        new_stack_addr = self.stack_addr - size
        new_stack_addr -= new_stack_addr % align
        try:
            self.stack_addr = new_stack_addr
            assert self.stack_base <= new_stack_addr
            yield self.mem(self.stack_addr, size)
        finally:
            ret_address = self.stack_addr
            self.stack_addr = max(old_stack_addr, self.stack_addr)
            if ret_address != new_stack_addr:
                raise Exception('stack reservations MUST be released in reverse order')

    def find_mapping(self, addr: int) -> FileMapping:
        idx = bisect.bisect(self.mappings__keys, addr)
        if idx > 0 and addr < self.mappings[idx-1][1].end:
            return self.mappings[idx-1]
        raise ValueError(f'address {addr:#x} not mapped')

    # SYMBOLS

    def __load_symbols(self):
        '''Find info about loaded objects and load their symbols'''
        # First we need to parse the binary ELF. This is essential;
        # without this we can't use the "debugger interface" to find
        # the rest of the objects, so no symbols at all.

        # Use auxv to locate program header of main executable, parse them
        # (we are using the raw structs here and not ELFFile, because this is
        # not the ELF file as seen on disk but its loaded version)
        phdr_base = self.auxv[AuxvField.PHDR.value]
        phdr_num = self.auxv[AuxvField.PHNUM.value]
        phdr = parse_program_header(self.core.structs, self.mem(phdr_base), phdr_num)
        # FIXME: use VMAs to locate base of executable, we'll need it to translate vaddrs, how tf does ld do it??
        _, vma = self.find_mapping(phdr_base)
        main_base = vma.start - vma.offset

        # Find r_debug (debugger interface entry point) through the DT_DEBUG tag
        try:
            dyn_seg = next(seg['p_vaddr'] for seg in phdr if seg['p_type'] == 'PT_DYNAMIC')
            dt_debug = next(parse_dynamic_section(self.core.structs,
                self.mem(main_base + dyn_seg), 'DT_DEBUG'))['d_ptr']
        except StopIteration:
            logger.warn('cannot find DT_DEBUG tag in binary. either it is a '
                'statically linked executable or it does not conform to the debugger '
                'interface, in which case info about shared libraries will be lost')
            # FIXME: for statically-linked executables, verify that they really don't
            # have a PT_DYNAMIC segment and maybe fall back to loading symbol table
            # by looking through the sections instead of the dynamic segment
            return
        if not dt_debug:
            logger.warn('DT_DEBUG tag not initialized. either linker does not '
                'follow debugger interface or who knows')
            return

        # Parse debug interface data
        r_version, r_map, r_brk, r_state, r_ldbase = self.mem(dt_debug).read_struct('<i4xQQi4xQ')
        if r_version != 1:
            logger.warn(f'unexpected/unsupported debugger interface version {r_version}. '
                'will try to parse anyway...')
        if r_state != RtState.CONSISTENT.value:
            logger.warn('coredump was taken when loaded objects list was in '
                'an unconsistent state. will try to parse anyway...')
        self.loaded_objects = list(RtLoadedObject.iterate(self.mem(), r_map))

        # Actually load the symbols of each object
        self.symbols = defaultdict(lambda: set())
        by_addr = defaultdict(lambda: defaultdict(lambda: set()))
        for obj in sorted(self.loaded_objects, key=lambda x: x.addr):
            self.__load_symbols_for(obj, by_addr)
        self.symbols = dict(self.symbols)
        self.symbols_by_type_by_addr = {
            stype: list(zip(*sorted(addrs.items()))) for stype, addrs in by_addr.items() }

    def __load_symbols_for(self, obj: RtLoadedObject, by_addr: dict[Symbol.Type, dict[int, list[Symbol]]]):
        # Find mapped disk file, open it
        if obj.addr != self.auxv.get(AuxvField.SYSINFO_EHDR.value):
            fname, _ = self.find_mapping(obj.ld)
            if fname not in self.mappings_mm:
                logger.warn(f'mappings for {fname} failed or were skipped, '
                    'its symbols will not be loaded')
                return
            ofname, mm = self.mappings_mm[fname]
            stream = BytesIO(mm)
        else:
            # VDSO is special bc kernel doesn't insert a mapping for it,
            # but its pages are always dumped so we can read from memory
            ofname, stream = b'[vdso]', self.mem(obj.addr)
        
        # Try to parse its symbols
        try:
            elf = elffile.ELFFile(stream)
            for table in elf.iter_sections():
                if not isinstance(table, sections.SymbolTableSection):
                    continue
                for sym in table.iter_symbols():
                    sym = Symbol.load(obj, sym)
                    if not sym.defined: continue
                    self.symbols[sym.name].add(sym)
                    by_addr[sym.type][sym.addr].add(sym)
            return obj
        except Exception:
            logger.warn(f'failed to parse symbols from {ofname}, skipping')
            return

    def get_symbols(self, name: str,
        stype: Optional[Symbol.Type]=Symbol.Type.FUNC,
        obj: Optional[RtLoadedObject]=None,
        exposed_only: bool=False,
    ) -> list[Symbol]:
        syms = getattr(self, 'symbols', {}).get(name, [])
        matches = lambda sym: \
            (obj is None or obj == sym.obj) and \
            (stype is None or stype == sym.type) and \
            (not exposed_only or sym.is_exposed)
        # FIXME: prioritize global, then weak, then local. also maybe visibility
        return [ sym for sym in syms if matches(sym) ]

    def get_symbol(self, name: str, *args, **kwargs) -> int:
        '''Resolve the address of a symbol (fails if none found)'''
        if not (syms := self.get_symbols(name, *args, **kwargs)):
            raise ValueError(f'no matching symbol found for {repr(name)}')
        return syms[0].addr

    def find_symbol(self, addr: int,
        stype: Symbol.Type=Symbol.Type.FUNC, look_before: int=5,
    ) -> dict:
        '''Try to find a symbol that addr is in'''
        assert not (stype is None)
        keys, buckets = getattr(self, 'symbols_by_type_by_addr', {}).get(stype, ([], []))
        idx = bisect.bisect(keys, addr)
        within_size = lambda sym, pos: not sym.size or pos < sym.size
        filter_syms = lambda baddr, syms: \
            ( sym for sym in syms if within_size(sym, addr - baddr) )
        syms = [ sym for n in range(min(look_before, idx))
            for sym in filter_syms(keys[idx-1-n], buckets[idx-1-n]) ]
        if syms: return syms[0]
        raise ValueError(f'no {stype.name} symbol found at {addr:#x}')

    # PATCHES

    def __patch_glibc(self):
        '''Patches glibc functions whose name ends in '_avx2' with a JMP to
        their generic siblings, to prevent unsupported instructions.
        
        IFUNCs are defined here:
        https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/i386/i686/multiarch/ifunc-impl-list.c
        https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/x86_64/multiarch/ifunc-impl-list.c
        but instead of a hardcoded list, we use a regexp to find them among symbols.
        '''
        # first we have to locate libc among loaded objects
        test_sym = getattr(self, 'symbols', {}).get('strchr', [])
        objs = { sym.obj for sym in test_sym if sym.is_callable and sym.is_exposed }
        if len(objs) != 1:
            logger.warn(f'cannot locate libc, found {len(objs)} candidates. skipping glibc patches...')
            return
        libc_obj = next(iter(objs))

        # collect libc function addresses
        collect_addresses = lambda syms: { sym.addr \
            for sym in syms if sym.obj == libc_obj and sym.is_function }
        libc_syms = { name: addrs for name, syms in self.symbols.items()
            if (addrs := collect_addresses(syms)) }

        # find candidates to patch
        hunks: list[tuple[int, int]] = []
        for name, addrs in libc_syms.items():
            if not (m := re.fullmatch(r'(.+)_(avx|avx2|avx512)(_.+)?', name)):
                continue
            replacements = ['_sse2', '_sse2_unaligned']
            replacements = [ fn for n in replacements if (fn := m.group(1) + n) in libc_syms ]
            if not replacements:
                logger.warn(f'cannot find replacement for {name}, not patching')
                continue
            target = next(iter(libc_syms[replacements[0]])) # FIXME: what if multiple?
            hunks += [ (addr, target) for addr in addrs ]

        # the dynamic linker (also provided by glibc) also has one function
        # responsible for saving the registers. since the available registers
        # depend on implemented SIMD extensions, we should patch that as well.
        # locate dynamic linker through AUXV, then its symbols:
        try:
            ld_obj = next(obj for obj in self.loaded_objects
                if obj.addr == self.auxv[AuxvField.BASE.value])
        except StopIteration:
            logger.warn(f'cannot find ld object. skipping ld patches...')
        else:
            ld_hunks = [
                ('_dl_runtime_resolve_xsavec', '_dl_runtime_resolve_fxsave'),
                ('_dl_runtime_resolve_xsave',  '_dl_runtime_resolve_fxsave'),
                ('_dl_runtime_profile_avx512', '_dl_runtime_profile_sse'),
                ('_dl_runtime_profile_avx',    '_dl_runtime_profile_sse'),
            ]
            for hunk in ld_hunks:
                try:
                    hunks.append(tuple( self.get_symbol(n, obj=ld_obj) for n in hunk ))
                except ValueError:
                    logger.warn(f'failed to patch {hunk[0]}, skiping patch...')

        # patch!
        for src, target in hunks:
            # jmp QWORD PTR [rip] (jumps to address following instruction)
            asm = b'\xff\x25\x00\x00\x00\x00'
            self.mem(src).write(asm + struct.pack('<Q', target))

    def __patch_pthreads(self):
        '''We can't emulate multithreading, but we can patch mutex functions
        so that all mutexes appear unlocked and *maybe* it will work'''
        if not hasattr(self, 'symbols'): return
        syms = [
            'mutex_lock', 'mutex_trylock', 'mutex_timedlock', 'mutex_unlock',
            'rwlock_wrlock', 'rwlock_trywrlock', 'rwlock_timedwrlock',
            'rwlock_rdlock', 'rwlock_tryrdlock', 'rwlock_timedrdlock',
            'rwlock_unlock',
            'cond_signal', 'cond_broadcast',
        ]
        for name in syms:
            candidates = self.get_symbols('pthread_' + name)
            if not candidates:
                logger.warn(f'failed to find {name}, skipping patch...')
            for sym in candidates:
                self.mem(sym.addr).write(b'\x48\x31\xC0\xC3')  # xor rax, rax; ret

    # EMULATION

    def format_code_addr(self, addr: int):
        '''Format a code address nicely by showing it as symbol + offset
        and shared object + offset, if possible.'''
        try:
            # try to find symbol first
            sym = self.find_symbol(addr)
        except ValueError:
            pass
        else:
            pos = addr - sym.addr
            pos = f'[{pos:#x}]' if pos else ''
            fname = sym.obj.name.decode(errors='ignore')
            offset = addr - sym.obj.addr
            return f'{addr:#x} {sym.name}{pos} ({fname}[{offset:#x}])'

        try:
            # try mapping next
            fname, vma = self.find_mapping(addr)
        except ValueError:
            pass
        else:
            fname = fname.decode(errors='replace')
            offset = vma.offset + (addr - vma.start)
            return f'{addr:#x} ({fname}[{offset:#x}])'

        return f'{addr:#x}'

    def format_exec_ctx(self):
        '''Collect info about the current execution context and return it
        as formatted text. Used for errors.'''
        tracer = self.stack_tracer
        trace = ([] if tracer is None else list(tracer.entries)) + [(
            self.emu.reg_read(x86_const.UC_X86_REG_RSP),
            self.emu.reg_read(x86_const.UC_X86_REG_RIP),
        )]
        format_call = lambda sp, ip: f'  at {self.format_code_addr(ip)}, sp={sp:#x}'
        return '\n'.join(format_call(*c) for c in trace)

    def __emulation_error(self, msg: str):
        return EmulationError(f'{msg}\n{self.format_exec_ctx()}')

    def __hook_mem(self, htype: int, addr: int, size: int, value: int):
        access_type, cause = UC_MEM_TYPES[htype]
        faddr = self.format_code_addr(addr)
        text = f'{access_type.lower()} of {size} bytes at {faddr}'
        if cause == 'PROT':
            raise self.__emulation_error(f'{text}, which is protected')
        if cause == 'UNMAPPED':
            try:
                fname, vma = self.find_mapping(addr)
            except ValueError:
                raise self.__emulation_error(f'{text}, which is invalid') from None
            assert fname not in self.mappings_mm
            raise self.__emulation_error(
                f'{text}, which belongs to a file that was skipped or failed to load')

    def __hook_insn_invalid(self):
        raise self.__emulation_error('invalid instruction')

    def __hook_intr(self, intno: Union[int, Literal['syscall', 'sysenter']]):
        if intno != 'syscall': # FIXME: x86-32
            raise self.__emulation_error(f'invalid interrupt {intno}')

        nr = self.emu.reg_read(x86_const.UC_X86_REG_RAX)
        try:
            nr = SyscallX64(nr)
        except ValueError as e:
            raise self.__emulation_error(f'invalid syscall {nr}') from None

        if not (handler := getattr(self, '_syscall_' + nr.name, None)):
            raise self.__emulation_error(f'"{nr.name}" syscall')
        nparams = len(signature(handler).parameters)
        result = handler(*( self.emu.reg_read(r) for r in SYSV_AMD_ARG_REGS[:nparams] ))
        if isinstance(result, Errno):
            result = -result.value
        else:
            assert isinstance(result, int) and result >= 0
        self.emu.reg_write(x86_const.UC_X86_REG_RAX, result)

    # FIXME: implement more archs and calling conventions
    def call(
        self, func: Union[int, str], *args: int,
        instruction_limit: int = 10000000, time_limit: int = 0,
    ) -> int:
        '''Emulate a function call.

        The first parameter is the address of the function to call. If it
        is a string, it will be resolved through `get_symbol()` first. The
        arguments to the function follow, which must be integers.

        If successful, returns the call result as an integer. Otherwise
        `EmulationError` should be raised; other errors possibly indicate a bug.

        Instruction or time limits can be placed on the call; the default is
        only a 10 million instruction limit. This can be changed through the
        `instruction_limit` and `time_limit` parameters. `0` indicate no limit,
        and `time_limit` is in microseconds.
        '''
        emu = self.emu
        func = self.get_symbol(func) if isinstance(func, str) else func
        ret_addr = self.stack_base
        emu.context_restore(self.emu_ctx)
        if self.stack_tracer: self.stack_tracer.clear()

        # set up arguments
        assert all(isinstance(x, int) for x in args), \
            'float and other non-integer arguments not implemented yet'
        assert all(-(1 << 63) <= x < (1 << 64) for x in args), \
            'arguments must be in u64 or s64 range (128 ints not implemented yet)'
        args = [ x & ~((~0) << 64) for x in args ]
        arg_regs = SYSV_AMD_ARG_REGS
        for p, reg in zip(args, arg_regs): emu.reg_write(reg, p)
        stack_args = args[len(arg_regs):]

        # finish stack (pad if necessary so that arguments end up on a multiple of 16)
        # (FIXME take advantage if current stack_addr % 16 < 8)
        if len(stack_args) % 1: stack_args.append(0)
        stack_args.insert(0, ret_addr)
        stack_args = struct.pack(f'<{len(stack_args)}Q', *stack_args)

        # emulate!
        with self.reserve(len(stack_args), align=16) as mem:
            mem.write(stack_args)
            emu.reg_write(x86_const.UC_X86_REG_RSP, mem.start)
            emu.emu_start(func, ret_addr, time_limit, instruction_limit)
            if emu.reg_read(x86_const.UC_X86_REG_RIP) != ret_addr:
                raise self.__emulation_error(f'Instruction/time limit exhausted')
            assert emu.reg_read(x86_const.UC_X86_REG_RSP) == mem.start + 8
            return emu.reg_read(x86_const.UC_X86_REG_RAX)

    # SYSCALLS

    def _syscall_futex(self, uaddr: int, cmd_: int, val: int, timeout: int, uaddr2: int, val3: int):
        try:
            cmd = FutexCmd.load(cmd_)
        except ValueError:
            raise self.__emulation_error(f'invalid futex syscall {cmd_}') from None

        if cmd.nr in { FutexCmd.Nr.WAKE, FutexCmd.Nr.WAKE_BITSET, FutexCmd.Nr.REQUEUE, FutexCmd.Nr.CMP_REQUEUE, FutexCmd.Nr.CMP_REQUEUE_PI, FutexCmd.Nr.WAKE_OP }:
            # wake operations are easy to implement: there are no other threads / processes, so just return 0
            # for some operations, we have to do prior checks / operations before the wake
            if cmd.nr in { FutexCmd.Nr.CMP_REQUEUE, FutexCmd.Nr.CMP_REQUEUE_PI }:
                if val3 >> 32:
                    raise self.__emulation_error('invalid futex CMP_REQUEUE syscall: val3 not u32')
                if self.mem(uaddr).read_struct('<I')[0] != val3:
                    return Errno.EAGAIN
            if cmd.nr == FutexCmd.Nr.WAKE_OP:
                try:
                    op = FutexOp.load(val3)
                except ValueError:
                    raise self.__emulation_error('invalid futex WAKE_OP syscall: val3 holds invalid op')
                oldval = self.mem(uaddr2).read_struct('<I')[0]
                self.mem(uaddr2).write_struct('<I', op.new_value(oldval))
            return 0

        # FIXME: if patch_lock is True, we could also patch out all waits and PI operations too
        raise self.__emulation_error(f'futex syscall {cmd}')
