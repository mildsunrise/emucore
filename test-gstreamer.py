import logging
logging.basicConfig(level=logging.INFO)

from emucore import EmuCore

emu = EmuCore("/tmp/core.gst-launch-1.0.780844")
pipeline = 0x5648e625c090

dstr = emu.call('gst_debug_bin_to_dot_data', pipeline, 0xFFFFFFFF)
print(emu.mem(dstr).read_str())
