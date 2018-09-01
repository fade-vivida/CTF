import struct

start_address = 0x400110
data_length = 0x401900 - 0x400110
fp = open('D:\\study\\ctf\\ctf\\ctf\\match_2018\\wangdingbei\\3\\reverse\\dump', 'wb')
for addr in range(start_address , start_address+data_length):
    fp.write(struct.pack("B" , Byte(addr)))

fp.close()