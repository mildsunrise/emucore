import logging
logging.basicConfig(level=logging.INFO)

from emucore import EmuCore

# opens core file, opens referenced files,
# initializes emulator (takes a while)
emu = EmuCore("/tmp/core.3007")

def get_font_description(font_addr: int) -> str:
    desc = emu.call('pango_font_describe', font_addr)
    dstr = emu.call('pango_font_description_to_string', desc)
    return emu.mem(dstr).read_str()

print(f'Font name: {get_font_description(0x555a4626b4e0)}')
