import os

f = open('mirror','rb')

data = f.read()
f.close()

data_inv = ""
for i in range(0,len(data))[::-1]:
    data_inv += data[i]

f = open('mirror_inv.png','wb+')
f.write(data_inv)
f.close()
