import os

def computeD(fn, e):
    (x, y, r) = extendedGCD(fn, e)
    #y maybe < 0, so convert it
    if y < 0:
        return fn + y
    return y

def extendedGCD(a, b):
    #a*xi + b*yi = ri
    if b == 0:
        return (1, 0, a)
    #a*x1 + b*y1 = a
    x1 = 1
    y1 = 0
    #a*x2 + b*y2 = b
    x2 = 0
    y2 = 1
    while b != 0:
        q = a / b
        #ri = r(i-2) % r(i-1)
        r = a % b
        a = b
        b = r
        #xi = x(i-2) - q*x(i-1)
        x = x1 - q*x2
        x1 = x2
        x2 = x
        #yi = y(i-2) - q*y(i-1)
        y = y1 - q*y2
        y1 = y2
        y2 = y
    return(x1, y1, a)

def fastExpMod(b, e, m):
    result = 1
    while e != 0:
        if (e&1) == 1:
            # ei = 1, then mul
            result = (result * b) % m
        e >>= 1
        # b, b^2, b^4, b^8, ... , b^(2^n)
        b = (b*b) % m
    return result


n = 0xFAC96621

e = 65537

p = 58979
q = 71339

fn = (p-1)*(q-1)

d = computeD(fn,e)

c_data =[
	1672633073,3311770533,1283079219,240009831,
	3054597787,1038500748,2228987423,2842990566,
  	1695485875,2230014076,3549221452,3887665888,
  	2037828943,2215641104,2144757573,1897745855,
  	1409460197,2738045777,518265848,578956990,
  	3747409480,2820148569,360111836,4040567611,
  	850141038,2472846912,3263356213,348519470,
  	2808472632,2144285786,1493380013,2589327550,
  	1598500293,1574833540,2381926101,3187156646,
  	1364882298,1112037534,950627360,3430900185,
  	641254423,3653155222
]

m_data = []
for i in range(42):
	m_data.append(fastExpMod(c_data[i],d,n))

for i in range(42):
	if(i%4==0) and(i!=0):
		print "\n"
	print str(m_data[i]).strip('L')+',',

# print m_data
# print hex(d)

