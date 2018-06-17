import os


def op_and(a,b):
	return a&b

def shift_l(a):
	return 1<<a

def check_not_zero(a):
	if a != 0:
		return 1
	return 0

def op_and_or(a,b,c):
	return (a&b)|(b&c)|(a&c)


#step 0:
check_flag = [0xA8,0x1C,0xAF,0xD9,0x00,0x6C,0xAC,0x02,0x9B,0x05,0xE3,0x68,0x2F,0xC7,0x78,0x3A,0x02,0xBC,0xBF,0xB9,0x4D,0x1C,0x7D,0x6E,0x31,0x1B,0x9B,0x84,0xD4,0x84,0x00,0x76,0x5A,0x4D,0x06,0x75]

delta = 0x5F3759DF

for i in range(9):
	tmp0 = check_not_zero(delta & shift_l(31))
	tmp0 ^= check_not_zero(delta & shift_l(7))
	tmp0 ^= check_not_zero(delta & shift_l(5))
	tmp0 ^= check_not_zero(delta & shift_l(3))
	tmp0 ^= check_not_zero(delta & shift_l(2))
	tmp0 ^= check_not_zero(delta & 1)
	delta = delta >> 1
	if tmp0 != 0:
		delta |= shift_l(31)
	else:
		delta &= ~shift_l(31)
	tmp1 = 0
	for j in range(0,4)[::-1]:
		tmp1 = tmp1*0x100 + check_flag[i*4+j]
	print hex(tmp1),hex(delta)
	tmp1 = tmp1 ^ delta

	for j in range(0,4):
		check_flag[i*4+j] = tmp1 & 0xff
		tmp1 = tmp1 >> 8

print check_flag





tmp0 = 0
tmp1 = 0
tmp2 = 0
delta = [0x31,0x62,0x93,0xC4,0x21,0x42,0x63,0x84,0x3D,0x7A,0xB7,0xF4]
# step 1
flag = []

ans = []
for i in range(36):
	flag.append(0)
	for m in range(0x100):
		flag[i] = m
		delta_tmp = delta[tmp0]
		add_carry = 0
		add_remain = 0
		for j in range(8):
			delta_j = check_not_zero(op_and(delta_tmp,shift_l(j)))
			flag_j = check_not_zero(op_and(flag[i],shift_l(j)))
			add_remain = delta_j ^ flag_j ^ add_carry
			add_carry = op_and_or(delta_j,flag_j,add_carry) 
			if add_remain != 0:
				flag[i] |= shift_l(j)
			else:
				flag[i] &= ~shift_l(j)

		delta_tmp = delta[4+tmp1]
		for j in range(8):
			delta_j = check_not_zero(op_and(delta_tmp,shift_l(j)))
			flag_j = check_not_zero(op_and(flag[i],shift_l(j)))
			add_remain = delta_j ^ flag_j ^ add_carry
			add_carry = op_and_or(delta_j,flag_j,add_carry) 
			if add_remain != 0:
				flag[i] |= shift_l(j)
			else:
				flag[i] &= ~shift_l(j)

		delta_tmp = delta[8+tmp2]
		for j in range(8):
			delta_j = check_not_zero(op_and(delta_tmp,shift_l(j)))
			flag_j = check_not_zero(op_and(flag[i],shift_l(j)))
			add_remain = delta_j ^ flag_j ^ add_carry
			add_carry = op_and_or(delta_j,flag_j,add_carry) 
			if add_remain != 0:
				flag[i] |= shift_l(j)
			else:
				flag[i] &= ~shift_l(j)
	
		for j in range(3):
			tp0 = check_not_zero(op_and(flag[i],shift_l(j)))
			tp1 = check_not_zero(op_and(flag[i],shift_l(7-j)))
			if tp0 != tp1:
				flag[i] |= shift_l(j)
			else:
				flag[i] &= ~shift_l(j)

			tp0 = check_not_zero(op_and(flag[i],shift_l(7-j)))
			tp1 = check_not_zero(op_and(flag[i],shift_l(j)))
			if tp0 != tp1:
				flag[i] |= shift_l(7-j)
			else:
				flag[i] &= ~shift_l(7-j)

			tp0 = check_not_zero(op_and(flag[i],shift_l(j)))
			tp1 = check_not_zero(op_and(flag[i],shift_l(7-j)))
			if tp0 != tp1:
				flag[i] |= shift_l(j)
			else:
				flag[i] &= ~shift_l(j)

		if flag[i] == check_flag[i]:
			ans.append(chr(m))
			#break
	
	tmp0 = tmp0 + 1
	if tmp0 == 4:
		tmp0 = 0
		tmp1 = tmp1 + 1
	if tmp1 == 4:
		tmp1 = 0
		tmp2 = tmp2 + 1
	if tmp2 == 4:
		tmp2 = 0

print ''.join(ans)