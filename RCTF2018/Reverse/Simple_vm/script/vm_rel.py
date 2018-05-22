import os

fp = open('p.bin','rb')

fp.seek(5,0)

de_flag = fp.read(0x20)
flag_len = len(de_flag)

for i in range(flag_len):
	print hex(ord(de_flag[i])),
print "\n"


cnt = 0x20
result = []
# method 1: force brute
# for i in range(0x20):
# 	for j in range(0,0x100):
# 		c = j
# 		tmp = cnt
# 		c = ~(c&tmp)&0xff
# 		tmp = c
# 		c = cnt
# 		c = ~(c&tmp)&0xff
# 		ttmp = c
# 		c = j
# 		c = ~(c&tmp)&0xff
# 		tmp = c
# 		c = ttmp
# 		res = (~(c&tmp))&0xff
# 		if res == ord(de_flag[i]):
# 			result.append(chr(j))
# 			#print chr(j),
# 	cnt = cnt + 1


# method 2:	the function is xor
for i in range(0x20):
	tmp = ord(de_flag[i])
	tmp = tmp ^ cnt
	cnt = cnt + 1
	result.append(chr(tmp))

print 'RCTF{' + ''.join(result) + '}'

