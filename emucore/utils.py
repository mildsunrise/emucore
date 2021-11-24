'''
Utilities for parsing the corefile, operating with memory ranges
and other low level stuff.
'''

import enum
from io import SEEK_CUR, SEEK_END, SEEK_SET, BytesIO, RawIOBase, UnsupportedOperation
import mmap
import struct
from typing import Any, BinaryIO, Callable, Iterator, NamedTuple, TypeVar, Union, Optional  
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from unicorn.unicorn import uc, Uc, x86_const
from elftools.elf.constants import P_FLAGS
from dataclasses import dataclass

# get real size of mmap'ed region, i.e. rounding up by PAGESIZE
mmapsize = lambda mm: ((mm.size() - 1) // mmap.PAGESIZE + 1) * mmap.PAGESIZE

# general serialization utilities

def read_struct(st: BinaryIO, fmt: Union[str, struct.Struct]):
    desc = struct.Struct(fmt) if isinstance(fmt, str) else fmt
    return desc.unpack(st.read(desc.size))

def write_struct(st: BinaryIO, fmt: Union[str, struct.Struct], *v: Any):
    desc = struct.pack(fmt, *v) if isinstance(fmt, str) else fmt.pack(*v)
    return st.write(desc)

def read_bstr(st: BinaryIO, allow_trunc: bool=False, max_size: Optional[int]=1024*1024) -> bytearray:
    res = bytearray()
    while (max_size is None or len(res) < max_size) and (car := st.read(1)):
        if not car[0]: return res
        res.append(car[0])
    if allow_trunc: return res
    raise Exception('no string terminator found within max_size')

def read_str(*kargs, encoding: str='utf-8', errors: str='strict', **kwargs) -> str:
    return read_bstr(*kargs, **kwargs).decode(encoding, errors)

def write_str(
    st: BinaryIO, x: Union[str, bytes, bytearray],
    encoding: str='utf-8', errors: str='strict',
    allow_invalid: bool=False,
):
    x = x.encode(encoding, errors) if isinstance(x, str) else x
    x = memoryview(x).cast('B')
    if not allow_invalid: assert all(b for b in x)
    fx = bytearray(len(x) + 1)
    fx[:len(x)] = x
    return st.write(fx)

class UnicornIO(RawIOBase):
    '''Exposes (part of) the memory of a Unicorn engine as a raw I/O stream'''
    uc: Uc
    start: int
    size: int
    offset: int

    def __init__(self, uc: Uc, start: int=0, size: Optional[int]=None, offset: int=0):
        if size is None:
            size = (1 << 64) - start
        assert 0 <= start <= (1 << 64)
        assert 0 <= size <= (1 << 64) - start
        self.uc, self.start, self.size, self.offset = uc, start, size, 0
        self.seek(offset)

    def readable(self):
        return True
    def writable(self):
        return True
    def seekable(self):
        return True

    def tell(self):
        return self.offset

    def seek(self, offset: int, whence: int=SEEK_SET):
        assert isinstance(offset, int)
        offset += { SEEK_SET: 0, SEEK_CUR: self.offset, SEEK_END: self.size }[whence]
        if not (0 <= offset <= self.size):
            # FIXME: should we also check it's a mapped position?
            raise ValueError(f'out-of-bounds offset: {offset}')
        self.offset = offset

    def truncate(self, size=None):
        raise UnsupportedOperation('fixed memory region, truncation not supported')

    # FIXME: check readable, writeable, seekable return True, check reexports accessible
    def read(self, size=-1) -> bytearray:
        assert isinstance(size, int)
        max_size = self.size - self.offset
        size = max_size if size == -1 else min(size, max_size)
        addr = self.start + self.offset
        assert 0 <= size < (1 << 64) and 0 <= addr < (1 << 64)
        result = self.uc.mem_read(addr, size)
        self.offset += size
        return result

    def write(self, b):
        max_size = self.size - self.offset
        b = memoryview(b).cast('B')
        if len(b) > max_size:
            raise ValueError(f'buffer of size {len(b)} exceeds bounds')
        addr = self.start + self.offset
        assert 0 <= addr < (1 << 64)
        self.uc.mem_write(addr, bytes(b))  # FIXME: find a way to prevent copy
        self.offset += len(b)

    def readall(self):
        return self.read()

    def readinto(self, b):
        b = memoryview(b).cast('B')
        b[:] = self.read(len(b))  # FIXME: prevent copy

# operations with memory ranges

T = TypeVar('T')

def sort_and_ensure_disjoint(x: Iterator[T], key: Callable[[T], tuple[int, int]]=lambda x: x) -> list[T]:
    '''Sorts a list of (start, end) memory ranges and
    ensures they are non-empty and don't overlap'''
    x = sorted(x, key=key)
    assert all(key(k)[0] < key(k)[1] for k in x)
    assert all(key(x1)[1] <= key(x2)[0] for x1, x2 in zip(x, x[1:]))
    return x

class VMA(NamedTuple):
    '''Represents a memory mapping (range + offset)'''
    start: int
    end: int
    offset: int

    @property
    def size(self):
        return self.end - self.start

    @property
    def offset_end(self):
        return self.offset + self.size

    def __str__(self):
        return f'{self.start:#x}-{self.end:#x} @ {self.offset:#x}-{self.offset_end:#x}'

    def __repr__(self):
        return f'VMA({self.start:#x}, {self.end:#x}, offset={self.offset:#x})'

    @staticmethod
    def simplify(vmas: Iterator['VMA']) -> list['VMA']:
        '''Collapse contiguous VMAs'''
        vmas = sorted(vmas, key=lambda v: v.start)
        result = []
        for vma in vmas:
            if result and result[-1].end == vma.start and result[-1].offset_end == vma.offset:
                result[-1] = VMA(result[-1].start, vma.end, result[-1].offset)
                continue
            result.append(vma)
        return result

# parsing of memory mapping related things

def parse_load_segments(elf: ELFFile) -> list[tuple[VMA, int]]:
    '''Parses the LOAD segments of an ELFFile into a list of (vma, flags) tuples'''
    return [ parse_load_segment(seg) for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD' ]

def parse_load_segment(seg: Segment):
    '''See parse_load_segments'''
    assert seg['p_filesz'] == seg['p_memsz']
    return VMA(seg['p_vaddr'], seg['p_vaddr'] + seg['p_filesz'], seg['p_offset']), seg['p_flags']

FileMapping = tuple[bytes, VMA]

def parse_file_note(note) -> list[FileMapping]:
    '''Parses the LOAD segments of an ELFFile into a list of (filename, vma) tuples'''
    assert note['page_size'] == 1
    parse_vma = lambda vma: VMA(vma['vm_start'], vma['vm_end'], vma['page_offset'])
    mappings = map(parse_vma, note['Elf_Nt_File_Entry'])
    mappings = list(zip(note['filename'], mappings))
    assert note['num_map_entries'] == len(mappings)
    return mappings

def elf_flags_to_uc_prot(flags: int) -> int:
    ''' Converts segment flags into Unicorn prot bitmask '''
    prot = 0
    if flags & P_FLAGS.PF_R: prot |= uc.UC_PROT_READ
    if flags & P_FLAGS.PF_W: prot |= uc.UC_PROT_WRITE
    if flags & P_FLAGS.PF_X: prot |= uc.UC_PROT_EXEC
    return prot

# parsing of other core notes

# FIXME: do we need to write RBX or BX?
X64_REGSTATE = [
    x86_const.UC_X86_REG_R15,
    x86_const.UC_X86_REG_R14,
    x86_const.UC_X86_REG_R13,
    x86_const.UC_X86_REG_R12,
    x86_const.UC_X86_REG_BP,
    x86_const.UC_X86_REG_BX,
    x86_const.UC_X86_REG_R11,
    x86_const.UC_X86_REG_R10,
    x86_const.UC_X86_REG_R9,
    x86_const.UC_X86_REG_R8,
    x86_const.UC_X86_REG_AX,
    x86_const.UC_X86_REG_CX,
    x86_const.UC_X86_REG_DX,
    x86_const.UC_X86_REG_SI,
    x86_const.UC_X86_REG_DI,
    x86_const.UC_X86_REG_AX,
    x86_const.UC_X86_REG_IP,
    x86_const.UC_X86_REG_CS,
    x86_const.UC_X86_REG_EFLAGS,
    x86_const.UC_X86_REG_SP,
    x86_const.UC_X86_REG_SS,
    x86_const.UC_X86_REG_FS_BASE,
    x86_const.UC_X86_REG_GS_BASE,
    x86_const.UC_X86_REG_DS,
    x86_const.UC_X86_REG_ES,
    x86_const.UC_X86_REG_FS,
    x86_const.UC_X86_REG_GS,
]

def parse_old_timeval(st: BinaryIO):
    sec, nsec = read_struct(st, '<2q')
    assert 0 <= nsec < 1000**3
    return sec * 1000**3 + nsec

class Siginfo(NamedTuple):
    si_signo: int  # signal number
    si_code: int   # extra code
    si_errno: int  # errno

@dataclass
class Prstatus(object):
    # COMMON DATA

    pr_info: Siginfo  # Info associated with signal
    pr_cursig: int  # Current signal
    pr_sigpend: int  # Set of pending signals
    pr_sighold: int  # Set of held signals

    pr_pid: int
    pr_ppid: int
    pr_pgrp: int
    pr_sid: int

    # times are nanoseconds since epoch
    pr_utime: int  # User time
    pr_stime: int  # System time
    pr_cutime: int  # Cumulative user time
    pr_cstime: int  # Cumulative system time

    # OTHER

    # GP registers (indexed by their Unicorn constant)
    regs: dict[int]

    # True if math co-processor being used
    pr_fpvalid: int

    @staticmethod
    def load(note):
        # pyelftools gives rawdata as a 'string', convert back to bytes
        st = BytesIO(note['n_descdata'].encode('latin-1'))

        # parse common data
        common = read_struct(st, '<' + '3i' + 'h2x' + 'QQ' + '4I')
        common = (Siginfo(*common[:3]),) + common[3:]
        times = [ parse_old_timeval(st) for _ in range(4) ]
        # FIXME: parse siginfo note too (same info?)

        # parse GP regs
        regs = X64_REGSTATE
        regs = dict(zip(regs, read_struct(st, f'<{len(regs)}Q')))
        # FIXME: parse FP regs and XSAVE regs too

        # parse rest
        pr_fpvalid, = read_struct(st, '<i4x')

        assert not st.read()
        return Prstatus(*common, *times, regs, pr_fpvalid)

def parse_auxv_note(note):
    # pyelftools gives rawdata as a 'string', convert back to bytes
    st = BytesIO(note['n_descdata'].encode('latin-1'))
    result = []
    while (pair := read_struct(st, '<2Q'))[0]: result.append(pair)
    rdict = dict(result)
    assert len(result) == len(rdict) and not st.read()
    return rdict

class AuxvField(enum.Enum):
    IGNORE        =  1    # entry should be ignored
    EXECFD        =  2    # file descriptor of program
    PHDR          =  3    # program headers for program
    PHENT         =  4    # size of program header entry
    PHNUM         =  5    # number of program headers
    PAGESZ        =  6    # system page size
    BASE          =  7    # base address of interpreter
    FLAGS         =  8    # flags
    ENTRY         =  9    # entry point of program
    NOTELF        = 10    # program is not ELF
    UID           = 11    # real uid
    EUID          = 12    # effective uid
    GID           = 13    # real gid
    EGID          = 14    # effective gid
    PLATFORM      = 15    # string identifying CPU for optimizations
    HWCAP         = 16    # arch dependent hints at CPU capabilities
    CLKTCK        = 17    # frequency at which times() increments
    # values 18 through 22 are reserved
    SECURE        = 23    # secure mode boolean
    BASE_PLATFORM = 24    # string identifying real platform, may differ from AT_PLATFORM
    RANDOM        = 25    # address of 16 random bytes
    HWCAP2        = 26    # extension of AT_HWCAP

    EXECFN        = 31    # filename of program

    # arch-specific:
    SYSINFO       = 32    # x86-32 only
    SYSINFO_EHDR  = 33

    MINSIGSTKSZ   = 51    # minimal stack size for signal delivery

# ABI-specific

SYSV_AMD_PARAM_REGS = [
    x86_const.UC_X86_REG_RDI,
    x86_const.UC_X86_REG_RSI,
    x86_const.UC_X86_REG_RDX,
    x86_const.UC_X86_REG_RCX,
    x86_const.UC_X86_REG_R8,
    x86_const.UC_X86_REG_R9,
]
