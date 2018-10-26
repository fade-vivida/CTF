import idaapi
import os

array_base = 0x106b64
tmp1 = idc.Dword(array_base + 19*4)
tmp2 = idc.Dword(array_base + 24*4)
#tmp3 = idc.Dword(array_base + 32*4)
#tmp4 = idc.Dword(array_base + 33*4)
print hex(tmp1^tmp2)
#print tmp3
#print tmp4