"""
Main module, exposes public API
"""

from collections import defaultdict
import ctypes
from io import DEFAULT_BUFFER_SIZE, BufferedRandom, BytesIO
import os
from typing import Callable, Optional, Union
from unicorn.unicorn import Uc, UcError, uc, x86_const
from elftools.elf import elffile
import mmap
import struct
import bisect

from .utils import \
    UnicornIO, read_struct, write_struct, read_bstr, read_str, write_str, \
    sort_and_ensure_disjoint, VMA, \
    parse_load_segments, parse_file_note, Prstatus, FileMapping, \
    parse_auxv_note, AuxvField, \
    parse_program_header, parse_dynamic_section, RtState, RtLoadedObject, \
    mmapsize, elf_flags_to_uc_prot, SYSV_AMD_PARAM_REGS

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
    # open resources (FIXME: make this class a context manager)
    emu: Uc
    core: elffile.ELFFile
    mmaps: list[mmap.mmap]

    # parsed info
    threads: list[Prstatus]
    mappings: list[FileMapping]
    auxv: dict[int, int]
    loaded_objects: list[RtLoadedObject]

    def __init__(
        self, filename: str,
        patch_libc: bool=True, mapping_load_kwargs={},
    ):
        self.mmaps = []

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

    def __load_core_segments(self):
        '''Read LOAD segments from core and map them'''
        load_segs = parse_load_segments(self.core)
        print(f'Mapping {len(load_segs)} LOAD segments...')
        corefd = self.core.stream.fileno()
        self.mmaps.append(mm := mmap.mmap(corefd, 0, mmap.MAP_PRIVATE, REQUIRED_PROT))
        for vma, flags in load_segs:
            prot = elf_flags_to_uc_prot(flags)
            assert vma.offset_end <= mmapsize(mm), 'segment exceeds file, malformed ELF'
            ptr = ctypes.byref((ctypes.c_char*1).from_buffer(mm, vma.offset))
            self.emu.mem_map_ptr(vma.start, vma.size, prot, ptr)

    def __load_mappings(self,
        whitelist: list[Union[str, bytes]]=[],
        blacklist: list[Union[str, bytes]]=['/dev/', '/proc/', '/sys/'],
        skip_invalid: bool=True, skip_special: bool=True,
        filename_map: Callable[[str], Optional[str]] = lambda x: x,
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
        blacklist = [ x.encode() if isinstance(x, str) else x for x in blacklist ]
        whitelist = [ x.encode() if isinstance(x, str) else x for x in whitelist ]

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

        # group by file, simplify
        file_mappings: dict[bytes, list[VMA]] = defaultdict(lambda: [])
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
        print('Skipped files:\n{}'.format('\n'.join(
            f' - {fn.decode(errors="replace")}'
                for fn in set(file_mappings) - set(mapped_filenames) )))
        file_mappings = { mapped_filenames[fn]: v for fn, v in file_mappings.items()
            if fn in mapped_filenames }
        total_mappings = sum(len(v) for v in file_mappings.values())
        print(f'Mapping {len(file_mappings)} files, {total_mappings} VMAs...')

        # map files (FIXME: catch open() errors and move on)
        for fname, vmas in file_mappings.items():
            with open(fname, 'rb') as f:
                self.mmaps.append(mm := mmap.mmap(f.fileno(), 0, mmap.MAP_PRIVATE, REQUIRED_PROT))
            for vma in vmas:
                # we know it's not writeable (otherwise it would be in the coredump)
                # so make it RX (FIXME look into sections?)
                prot = uc.UC_PROT_READ | uc.UC_PROT_EXEC
                assert vma.offset_end <= mmapsize(mm), \
                    f'invalid mapping on {fname}: {vma}'
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
        loaded_objects = list(RtLoadedObject.iterate(self.mem(), r_map))

        # Actually load the symbols of each object
        self.loaded_objects = { obj.addr:
            self.__load_symbols_for(obj) for obj in loaded_objects }

    def __load_symbols_for(obj: RtLoadedObject):
        # Load dynamic symbols (this is guaranteed info, it doesn't depend
        # on mappings / disk files at all, so start by loading these first)
        return obj

    def __patch_libc(self):
        pass # TODO

    def get_mapping(self, addr: int) -> FileMapping:
        idx = bisect.bisect([ x[1].start for x in self.mappings ], addr)
        if idx > 0 and addr < self.mappings[idx-1][1].end:
            return self.mappings[idx-1]
        raise ValueError(f'address {addr:#x} not mapped')

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
    def call(self, func: int, *params: tuple[int], stack: bytearray=bytearray(),
        stack_base: int = 0x7ffffffff0000000,
        # resources
        stack_size: int = 1024 * 1024, instruction_limit: int = 10000, time_limit: int = 0,
    ) -> int:
        emu = self.emu
        orig_stack = stack
        ret_addr = stack_base

        # prepare stack, set registers
        assert len(stack) % 8 == 0
        assert all(isinstance(x, int) for x in params), 'float arguments not implemented yet'
        param_regs = SYSV_AMD_PARAM_REGS
        for p, reg in zip(params, param_regs):
            emu.reg_write(reg, p)
        stack_params = params[len(param_regs):] # TODO: pass stack params
        # TODO: align to 16-bytes + 8 (now or before params?)
        stack = struct.pack('<Q', ret_addr) + bytes(stack)

        # map stack area
        PAGESIZE = emu.query(uc.UC_QUERY_PAGE_SIZE)
        assert stack_base % PAGESIZE == 0
        stack_size += len(stack)
        stack_size = ((stack_size - 1) // PAGESIZE + 1) * PAGESIZE
        emu.mem_map(stack_base, stack_size, uc.UC_PROT_ALL)
        stack_entry = stack_base + stack_size - len(stack)
        emu.mem_write(stack_entry, stack)

        # register hooks
        hooks = []
        syscall = None
        def hook_intr(_self, intno: int, _):
            nonlocal syscall
            syscall = intno
            emu.emu_stop()
        hooks.append(emu.hook_add(uc.UC_HOOK_INTR, hook_intr))
        def hook_mem(_self, htype: int, address: int, size: int, value: int, _):
            # FIXME: check if unmapped or skipped mapping, raise as error
            print(f'mem: {htype} addr={address:#x} size={size} value={value}')
        hooks.append(emu.hook_add(uc.UC_HOOK_MEM_INVALID, hook_mem))

        # emulate!
        emu.reg_write(x86_const.UC_X86_REG_RSP, stack_entry)
        try:
            emu.emu_start(func, ret_addr, time_limit, instruction_limit)
        except UcError as e:
            raise Exception(f'Unknown Unicorn error ({self.format_exec_ctx()})') from e
        finally:
            # collect result, clean up
            for hook in hooks: emu.hook_del(hook)
            orig_stack[:] = emu.mem_read(stack_base, len(orig_stack))
            emu.mem_unmap(stack_base, stack_size)
        if emu.reg_read(x86_const.UC_X86_REG_RIP) != ret_addr:
            raise Exception(f'Limits exhausted ({self.format_exec_ctx()})')
        assert emu.reg_read(x86_const.UC_X86_REG_RSP) == stack_entry + 8
        return emu.reg_read(x86_const.UC_X86_REG_RAX)


# stop reasons:
#  - resources
#  - bug in code or emulator: access to unmapped memory, prot access, illegal instruction
#  - not supported: code uses syscall
#  - code tried to access skipped mapping
