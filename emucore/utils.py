'''
Utilities for parsing the corefile, operating with memory ranges
and other low level stuff.
'''

from io import BytesIO
import mmap
import struct
from typing import BinaryIO, Callable, Iterator, NamedTuple, TypeVar
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from unicorn.unicorn import uc, x86_const
from elftools.elf.constants import P_FLAGS
from dataclasses import dataclass

def read_struct(st: BinaryIO, fmt: str):
    desc = struct.Struct(fmt)
    return desc.unpack(st.read(desc.size))

# get real size of mmap'ed region, i.e. rounding up by PAGESIZE
mmapsize = lambda mm: ((mm.size() - 1) // mmap.PAGESIZE + 1) * mmap.PAGESIZE

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

        # parse GP regs
        regs = X64_REGSTATE
        regs = dict(zip(regs, read_struct(st, f'<{len(regs)}Q')))

        # parse rest
        pr_fpvalid, = read_struct(st, '<i4x')

        assert not st.read()
        return Prstatus(*common, *times, regs, pr_fpvalid)

# ABI-specific

SYSV_AMD_PARAM_REGS = [
    x86_const.UC_X86_REG_RDI,
    x86_const.UC_X86_REG_RSI,
    x86_const.UC_X86_REG_RDX,
    x86_const.UC_X86_REG_RCX,
    x86_const.UC_X86_REG_R8,
    x86_const.UC_X86_REG_R9,
]
