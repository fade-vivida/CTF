import os

check_str =[
  0x01, 0x95, 0x66, 0x3E, 0x1B, 0x56, 0x64, 0x2C, 0x28, 0x0A, 
  0x9A, 0x04, 0xAD, 0x0C, 0xC8, 0xD9
]

def sar(x,i):
    sign_bit = x&0x80
    f = 0
    if sign_bit:
        f = 0xff00
    return ((x>>i)|(f>>i))&0xff

res = ''
for i in range(16):
    tmp2 = 0
    tmp3 = 0
    for j in range(0x20,0x80):
        if i == 0:
            tmp1 = j
        tmp2 = ( sar(tmp1,2) | (tmp1 << 6) ) ^ 0xae
        tmp2 &= 0xff
        if (chr(j) == '1') and (i == 0):
            print hex(tmp2)
        tmp2 = ((tmp2 << 5) | sar(tmp2,3)) ^ 0x66
        tmp2 &= 0xff
        if (chr(j) == '1') and (i == 0):
            print hex(tmp2)
        
        tmp3 = j ^ ~(sar(tmp2,1) | (tmp2 << 7) | sar(j,4))
        tmp3 &= 0xff
        if (chr(j) == '1') and (i == 0):
            print hex(tmp3)
        if tmp3 != check_str[i]:
            continue
        #tmp1 = ~tmp3
        res += chr(j)#print chr(j),
        break
    tmp1 = ~check_str[i]
    tmp1 &= 0xff
    #print '\n'
print res