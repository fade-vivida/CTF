import os
import idaapi

addr = 0x21e0

for i in range(6):
    tmp = Dword(addr+i*4)
    tmp = (addr+tmp) & 0xffffffff
    print hex(tmp),
