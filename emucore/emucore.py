"""
Main module, exposes public API
"""

from collections import defaultdict
import ctypes
from io import DEFAULT_BUFFER_SIZE, BufferedRandom, BytesIO
import os
from typing import Callable, Optional, Union
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
    parse_program_header, parse_dynamic_section, RtState, RtLoadedObject, \
    mmapsize, elf_flags_to_uc_prot, SYSV_AMD_ARG_REGS

from .syscall import SyscallX64

# FIXME: a lot of these asserts should be exceptions, we should have a class
# FIXME: proper log system

# FIXME: in the memory mapping phase, the code assumes that our
# PAGESIZE is the same as the core dump's:
#  - if ours is higher: mmapping will fail if given an unaligned offset
#  - if core dump's is higher: last-page rounding will not match up with the VMA rounding
# Also, Unicorn engine page size must not be higher, checked below

# minimum access required by Unicorn on mapped areas, otherwise behaviour is undefined
REQUIRED_PROT = mmap.PROT_READ | mmap.PROT_WRITE

class EmuCore(object):
    SymbolEntry = tuple[RtLoadedObject, dict]

    # open resources (FIXME: make this class a context manager)
    emu: Uc
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
    symbols: dict[str, list[SymbolEntry]]

    emu_ctx: UcContext

    # stack management
    stack_base: int
    stack_size: int
    stack_addr: int

    def __init__(
        self, filename: str,
        patch_libc: bool=True, mapping_load_kwargs={},
        stack_addr: int = 0x7f10000000000000, stack_size: int = 16 * 1024 * 1024,
    ):
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

        # Map everything into emulator
        print('Mapping memory...')
        if self.auxv[AuxvField.PAGESZ.value] != mmap.PAGESIZE:
            print('WARNING: page size should match with the host')
        assert self.emu.query(uc.UC_QUERY_PAGE_SIZE) <= mmap.PAGESIZE
        # (first core segments, then RO mappings over any uncovered areas)
        self.__load_core_segments()
        self.__load_mappings(**mapping_load_kwargs)

        # Load symbols from binary and loaded objects
        self.__load_symbols()

        # Post-load fixups
        if patch_libc:
            self.__patch_libc()

        # Map our stack area
        self.stack_addr, self.stack_size = stack_addr, stack_size
        self.stack_base = stack_addr - stack_size
        self.emu.mem_map(self.stack_base, self.stack_size, uc.UC_PROT_ALL)

    # MEMORY MAPPING

    def __load_core_segments(self):
        '''Read LOAD segments from core and map them'''
        load_segs = parse_load_segments(self.core)
        print(f'Mapping {len(load_segs)} LOAD segments...')
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
            or any(pref.startswith(fn) for pref in blacklist)
        file_filter = lambda fn: \
            any(pref.startswith(fn) for pref in whitelist) or not file_skipped(fn)
        mapped_filenames = { fn: fn2 for fn in file_mappings
            if file_filter(fn) and (fn2 := filename_map(fn)) != None }
        print('Skipped files with VMAs:\n{}'.format('\n'.join(
            f' - {fn.decode(errors="replace")}'
                for fn, vmas in file_mappings.items() if fn not in mapped_filenames and vmas )))
        file_mappings = { fn: v for fn, v in file_mappings.items() if fn in mapped_filenames }
        total_mappings = sum(len(v) for v in file_mappings.values())
        print(f'Mapping {len(file_mappings)} files, {total_mappings} VMAs...')

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

    def mem(self, start: int=0, size: Optional[int]=None, offset: int=0, buffer_size: int=DEFAULT_BUFFER_SIZE):
        '''Returns a binary I/O stream over (a region of) memory

        First two arguments restrict the accessible memory range,
        with `start` being exposed at offset 0.

        The `offset` parameter calls seek() on the returned stream.
        '''
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

    def get_mapping(self, addr: int) -> FileMapping:
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
        _, vma = self.get_mapping(phdr_base)
        main_base = vma.start - vma.offset

        # Find r_debug (debugger interface entry point) through the DT_DEBUG tag
        try:
            dyn_seg = next(seg['p_vaddr'] for seg in phdr if seg['p_type'] == 'PT_DYNAMIC')
            dt_debug = next(parse_dynamic_section(self.core.structs,
                self.mem(main_base + dyn_seg), 'DT_DEBUG'))['d_ptr']
        except StopIteration:
            print('WARNING: cannot find DT_DEBUG tag in binary. either it is a '
                'statically linked executable or it does not conform to the debugger '
                'interface, in which case info about shared libraries will be lost')
            # FIXME: for statically-linked executables, verify that they really don't
            # have a PT_DYNAMIC segment and maybe fall back to loading symbol table
            # by looking through the sections instead of the dynamic segment
            return
        if not dt_debug:
            print('WARNING: DT_DEBUG tag not initialized. either linker does not '
                'follow debugger interface or who knows')
            return

        # Parse debug interface data
        r_version, r_map, r_brk, r_state, r_ldbase = self.mem(dt_debug).read_struct('<i4xQQi4xQ')
        if r_version != 1:
            print(f'WARNING: unexpected/unsupported debugger interface version {r_version}. '
                'will try to parse anyway...')
        if r_state != RtState.CONSISTENT.value:
            print('WARNING: coredump was taken when loaded objects list was in '
                'an unconsistent state. will try to parse anyway...')
        self.loaded_objects = list(RtLoadedObject.iterate(self.mem(), r_map))

        # Actually load the symbols of each object
        self.symbols = defaultdict(lambda: [])
        for obj in sorted(self.loaded_objects, key=lambda x: x.addr):
            self.__load_symbols_for(obj)
        self.symbols = dict(self.symbols)

    def __load_symbols_for(self, obj: RtLoadedObject):
        # Find mapped disk file, open it
        if obj.addr != self.auxv.get(AuxvField.SYSINFO_EHDR.value):
            fname, _ = self.get_mapping(obj.ld)
            if fname not in self.mappings_mm:
                print(f'WARNING: mappings for {fname} failed or were skipped, '
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
                    self.symbols[sym.name].append((obj, sym.entry))
            return obj
        except Exception:
            print(f'WARNING: failed to parse symbols from {ofname}, skipping')
            return

    def get_function_symbol(self, name: str) -> int:
        '''Resolve the address of a function by looking at loaded symbols'''
        syms = getattr(self, 'symbols', {}).get(name, [])
        syms = [ sym for sym in syms if sym[1]['st_shndx'] != 'SHN_UNDEF'
            and sym[1]['st_info']['type'] == 'STT_FUNC' ]
        if not syms:
            raise ValueError(f'no function symbol found for {repr(name)}')
        # FIXME: prioritize global, then local, then weak. also maybe visibility
        obj, sym = syms[0]
        return obj.addr + sym['st_value']

    # PATCHES

    def __patch_libc(self):
        if not hasattr(self, 'loaded_objects'): return
        pass # TODO

    # EMULATION

    def format_code_addr(self, addr: int):
        # for now, print its file + offset
        # (FIXME: improve, show symbol if available)
        try:
            fname, vma = self.get_mapping(addr)
        except ValueError:
            return f'{addr:#x}'
        fname = fname.decode(errors='replace')
        offset = vma.offset + (addr - vma.start)
        return f'{fname}[{offset:#x}]'

    def format_exec_ctx(self):
        # FIXME: backtrace?
        ip = self.format_code_addr(self.emu.reg_read(x86_const.UC_X86_REG_RIP))
        sp = self.emu.reg_read(x86_const.UC_X86_REG_RSP)
        return f'ip={ip} sp={sp:#x}'

    # FIXME: implement more archs and calling conventions
    def call(
        self, func: Union[int, str], *args: int,
        instruction_limit: int = 10000, time_limit: int = 0,
    ) -> int:
        emu = self.emu
        func = self.get_function_symbol(func) if isinstance(func, str) else func
        ret_addr = self.stack_base
        emu.context_restore(self.emu_ctx)

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

        # define hooks
        def hook_intr(intno: Union[int, str]):
            try:
                nr = SyscallX64(emu.reg_read(x86_const.UC_X86_REG_RAX))
            except ValueError as e:
                raise Exception(f'invalid syscall ({intno})') from e
            else:
                raise Exception(f'code attempted {nr.name} syscall ({intno})')
        def hook_mem(_self, htype: int, address: int, size: int, value: int, _):
            # FIXME: check if unmapped or skipped mapping, raise as error
            print(f'mem: {htype} addr={address:#x} size={size} value={value}')
        hooks = [
            *((uc.UC_HOOK_INSN, (lambda k: lambda _self, _: hook_intr(k))(kind), None, 1, 0, ins) for ins, kind in
                [(x86_const.UC_X86_INS_SYSCALL, 'syscall'), (x86_const.UC_X86_INS_SYSENTER, 'sysenter')]),
            (uc.UC_HOOK_INTR, lambda _self, no, _: hook_intr(no)),
            (uc.UC_HOOK_MEM_INVALID, hook_mem),
        ]

        # emulate!
        with self.reserve(len(stack_args), align=16) as mem:
            mem.write(stack_args)
            emu.reg_write(x86_const.UC_X86_REG_RSP, mem.start)
            try:
                hook_handles = []
                for hook in hooks: hook_handles.append(emu.hook_add(*hook))
                emu.emu_start(func, ret_addr, time_limit, instruction_limit)
            except UcError as e:
                raise Exception(f'Unknown Unicorn error ({self.format_exec_ctx()})') from e
            finally:
                for hook in hook_handles: emu.hook_del(hook)
            if emu.reg_read(x86_const.UC_X86_REG_RIP) != ret_addr:
                raise Exception(f'Limits exhausted ({self.format_exec_ctx()})')
            assert emu.reg_read(x86_const.UC_X86_REG_RSP) == mem.start + 8
            return emu.reg_read(x86_const.UC_X86_REG_RAX)


# stop reasons:
#  - resources
#  - bug in code or emulator: access to unmapped memory, prot access, illegal instruction
#  - not supported: code uses syscall
#  - code tried to access skipped mapping
