from typing import Optional
from ctypes import byref, cast, Structure, CDLL, POINTER, c_void_p, c_uint64, c_size_t
from os.path import dirname, join, isfile

try:
    from unicorn.unicorn import uc, Uc, UcError, _uc, UC_HOOK_CODE_CB, uc_hook_h
except ImportError as e:
    raise ImportError('could not import Unicorn internals') from e

__all__ = ['StackTracer']

# load shared library

tracer_file = join(dirname(__file__), 'tracer.so')

try:
    tracer_file = CDLL(tracer_file)
except OSError as e:
    raise ImportError('could not load tracer library') from e

cast(tracer_file.uc_reg_read, POINTER(c_void_p))[0] = cast(_uc.uc_reg_read, c_void_p)
hook_block = cast(tracer_file.hook_block, UC_HOOK_CODE_CB)

# interface code

class Entry(Structure):
    _fields_ = [("sp", c_uint64),
                ("ip", c_uint64)]
class Data(Structure):
    _fields_ = [("capacity", c_size_t),
                ("size", c_size_t),
                ("entries", POINTER(Entry))]

class StackTracer(object):
    data: Data
    handle: Optional[uc_hook_h]

    def __init__(self, capacity: int):
        self._entries = (Entry * capacity)()
        entries = cast(byref(self._entries), POINTER(Entry))
        self.data = Data(capacity, 0, entries)
        self.handle = None

    def clear(self):
        self.data.size = 0

    @property
    def entries(self) -> list[tuple[int, int]]:
        return [ (self._entries[n].sp, self._entries[n].ip) for n in range(self.data.size) ]

    def set_attached(self, attached: bool, emu: Uc):
        '''Attach or detach the hooks if needed. Uc instance is passed
        here to avoid creating reference cycles.'''
        if not (self.handle is None) == attached: return
        if attached:
            handle = uc_hook_h()
            err = _uc.uc_hook_add(
                emu._uch, byref(handle), uc.UC_HOOK_BLOCK, hook_block,
                cast(byref(self.data), c_void_p),
                c_uint64(1), c_uint64(0)
            )
            if err != uc.UC_ERR_OK: raise UcError(err)
            self.handle = handle.value
        else:
            emu.hook_del(self.handle)
            self.handle = None
