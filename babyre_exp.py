import idaapi
import string
import base64

my_base64table = "R9Ly6NoJvsIPnWhETYtHe4Sdl+MbGujaZpk102wKCr7/0Dg5zXAFqQfxBicV3m8U"
std_base64table ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
s = "eQ4y46+VufZzdFNFdx0zudsa+yY0+J2m"
#s = "SUCTF{wh0_1s_{0ur_d4ldy}"
s = "FLAG{2019_a_simple_mips}"
s = s.translate(string.maketrans(my_base64table,std_base64table))
#print base64.b64decode(s)
print base64.b64encode(s)

m = "ekN5Y3tsc2pCX2ZfSjU5aFlVXzk1aEp9"
start = 0x401078

for i in range(len(m)):
    op = GetMnem(start)
    if op == 'li':
        byte = ord(m[i])
        PatchByte(start+3,byte)
    start += 0x18