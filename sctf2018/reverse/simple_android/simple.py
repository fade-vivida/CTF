import os

step1 = 1
if step1 == 0:
	str1 = 'E82038F4B30E810375C8365D7D2C1A3F'
	str1_len = len(str1)

	fp = open('test.zip','rb')

	str2 = fp.read()
	fp.close()

	byte_array2 = []
	for i in range(len(str2)):
		byte_array2.append(ord(str2[i]))
	byte_array2[0] = 113
	byte_array2[1] = 114
	byte_array2[2] = 10
	byte_array2[3] = 8

	tmp = []
	for i in range(256):
		tmp.append(i)

	j = 0
	for i in range(256):
		j = (tmp[i] + j + ord(str1[i%str1_len])) % 256
		k = tmp[i]
		tmp[i] = tmp[j]
		tmp[j] = k

	str2_len = len(byte_array2)
	result = []
	m = 0
	k = 0

	for i in range(str2_len):
		m = ( m + 1 ) % 256
		k = ( tmp[m] + k ) % 256
		x = tmp[k]
		tmp[k] = tmp[m]
		tmp[m] = x
		de_tmp = tmp[(tmp[m] + tmp[k]) % 256] ^ byte_array2[i]
		result.append(chr(de_tmp))

	fp = open('result.dex','wb')
	fp.write(''.join(result))
	fp.close()


def turn_point(n,point_a):
	cnt = n
	while True:
		point_t = point_a[0]
		for i in range(24):
			point_a[i] = point_a[i+1]
		point_a[24] = point_t
		cnt = cnt - 1
		if cnt == 0:
			break

def check_point(point_a):
	point_sum = 0
	for i in range(5):
		point_sum += point_a[i*6]
		point_sum += point_a[4*(i+1)]
	#print point_sum
	if point_sum >= 10:
		return 1
	else:
		return 0

def print_point(point_a):
	for i in range(25):
		print point_tmp[i],
		if (i+1)%5==0:
			print '\n'
	print '\n'

step2 = 0
if step2 == 0:
	for i in range(0x100):
		point_tmp = []
		x = (828309504 + (i<<8)) + 255
		#print hex(i),hex(x)
		for j in range(25):
			if (x%2) == 1:
				point_tmp.append(1)
			else:
				point_tmp.append(0)
			x = x/2
		flag = check_point(point_tmp)
		if flag == 1:
			#print_point(point_tmp)
			turn_point(4,point_tmp)
			#print_point(point_tmp)
			flag = check_point(point_tmp)
			if flag == 1:
				#print_point(point_tmp)
				print i,chr(i)
