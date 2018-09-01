import os

f = open('./shanghai.txt','rb')

data = f.read()
f.close()

result = ''

key = 'icqvigenere'
cnt = 0
for i in range(len(data)):
	if data[i].islower():
		tmp = (ord(data[i]) - ord(key[cnt]) + 26 )%26 + 0x61
		cnt += 1
		result += chr(tmp)
		if cnt == len(key):
			cnt = 0
	else:
		result += data[i]


print result
