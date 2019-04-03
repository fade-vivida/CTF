import os
fp = open('exact.txt','rb')
data = fp.readlines()
f = open('exact1.txt','wb')
for i in data:
    f.write(i.strip('+'))
fp.close()
f.close()