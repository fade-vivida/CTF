import os

index = [11,8,7,7,8,12,3,2,16,6,13,5,7,16,4,1,0,15,16,8,3,6,14,16,0,8,6,9,12,14,13,11,15,7,11,14]

print len(index)

f = open('./heap','rb')
data = f.read()

result = []
for i in range(36):
	result.append(chr(ord(data[0xe0+index[i]*4])+0x2d))

print 'flag{'+''.join(result)+'}'

f.close()