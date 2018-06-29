import os
import sys   
sys.setrecursionlimit(1000000)

str_a = "z3EgyCQtwdWZFC5tGYZkaL==|-187|DBZjxdf=;a3FhzDRuxeXqL0Mkyh5qHYduFi4lLZstGPlubM==|204|EAMkyetqGM==;g3LnfJXadkDGMJKuAUjwMUn9|-24|KGWqekzwMS==;h3CkflEkSWD7g2kseJXrelo7dZBrelBaNAwkSXTrBVabNA1bSAL8SGH7em1xSm4aiAMogKYbelEkiT==|-205|LHBrflaxNT==;v3QytzSyGKR7u2ygsXLfta49szc7ta1WBYZjszb7PK1VBXVjDJc9tdM0uOAlZXW9|-139|ZVtftzolBH==;i3NphLZcfmFcPqbpfqh0eL0=|108|MIksgmo=;c3HjbFTwzgCmaj5sIV0=|128|GCmmagvsIO==;p3UwoSGjmtMjH25oqB==|219|TPdzntifVB==;u2bcAXYkrWLkP3HeFJ0nANjoPNH1sc4wsy5zqWVoG29aPKV0ATQfvN0=|198|YUmesya=;p3UwoSGjmtejqB==|-145|TP0zntv=;t3YasWKnqxQIsWYeqbrdrxa9|119|XT4drxz=;l3QskOCfipIfR259|-175|PL8vjpebRX==;j2Eahnm2DCNliI1dT3V8UB47iHxwPCyuEnmmB3WiNY12B3Vyhq0uj3OqiMAdgnGrDBceEC19hrA0iCOzNMWdiBA9|-229|NKJthnczQLJxinp=;w3RzuaTmHPA7veXqAYW9KUzmCLl2QPAyvb1CCYWkEbIhG3RzuaT0HMkgtaooCLl2QPAyvL1DCY4kEKc7veXqAYc9KqzmDVAhG3RzuaTdHMkgtaorCLl2QPAyRb1WCWogvUckLUzhCKc7veXqAY89JKzECZIhDWogvKchG3RzuaTbHMkgtao2CLl2QPAytV1DCY4kFqc7veXqAYy9KqzmDVW2CLl2QPAyvr1DCY4kELuhG3RzuaTBHMggJKzECZMhDWogsUchDVShG3RzuaTLHMggJUzECYEhDWogtUchDWIgLUzgCKpECZuhCKc7veXqAX89KazXCWogvKckLUzbCKckEUc7veXqAYu9KqzmDVApCLl2QPAyuV1DCY4kEbAhG3RzuaTrHMggJKzYCWogRqckEackJqy2FapECZShCKckFbIhG3RzuaTIHNWgGKopFKpmDUBIvX9Btd9LAac7veXqAXI9KazECYohDWogAfAaCKc7veXqAYA9KazeDVArEKc7veXqAYI9KaznDVW2CLl2QPAysb1FCWkgtao1CKc7veXqAYk9KazZCW0gLqzGCWogRKchDUAoAachDYghDVAoFUc7veXqAY09LKzDCY4kGUchG3RzuaTpHNWgELykEbSktaoaKPTMAac7veXqAZy9KazXCYgktKckFUc7veXqAZc9KazYCY0ktKcktKc7veXqAZg9KazWCWogKqzmDVIhCKpWCY0ktKchDWogKqzmDVArCKchG3RzuaTTHMggLUz1CKo5GKc7veXqAWA9KazECWkgtaoqEqchDVWqFKc7veXqAWE9KazECWkgtaoqEachDVErCLlqRPJ1ue4yvaQeKKQeMqQePqQeuqQeMUQeNUQeQaQeRUQesqQeuKQewUQewKQewaQeIKQeIaQeI30=|-8|AZAguac="

Upper = ""
for i in range(0x41,0x41+26):
	Upper += chr(i)
Lower = ""
for i in range(0x61,0x61+26):
	Lower += chr(i)
Number = "0123456789"
SpecialTable = "+/="
print Upper
print Lower

def search(a,base_str):
	for i in range(len(base_str)):
		if a == base_str[i]:
			return i

def base_64_s(ss,base_str):
	tmp = ""
	for i in range(0,len(ss),4):
		index0 = search(ss[i],base_str)
		index1 = search(ss[i+1],base_str)
		index2 = search(ss[i+2],base_str)
		index3 = search(ss[i+3],base_str)
		ch1 = (index0 << 2) | ((index1 >> 4) & 3)
		ch2 = ((index1 & 0xf) << 4) | ((index2 >> 2) & 0xf)
		ch3 = ((index2 & 0x3) << 6) | index3
		tmp += chr(ch1)+chr(ch2)+chr(ch3)
	return tmp

def gen_Letter(x):
	tmp = ""
	for i in range(26):
		tmp += Upper[(i+x)%26]
	for i in range(26):
		tmp += Lower[(i+x)%26]
	return tmp

list_0 = str_a.split(';')
for i in range(len(list_0)):
	tmp = list_0[i]
	list_1 = tmp.split('|')
	a = list_1[0]
	b = list_1[1]
	c = list_1[2]
	if len(list_1)==3:
		base64_str = gen_Letter(int(b))
		base64_str += Number
		base64_str += SpecialTable
		a = base_64_s(a,base64_str)
		c = base_64_s(c,base64_str)
		print 'function '+c+a


	#print list_s[i]

def D(a,b):
	if b == 0:
		return a
	else:
		return D((a^b)&0xff,((a&b)<<1)&0xff)

def A(a):
	return D(~a,1)

def E(a,b):
	return D(a,A(b))


# F(r,n)
# {
# 	var a=0;
# 	while(n)
# 	{
# 		if(n&1)
# 		{
# 			a=D(a,r)
# 		}
# 		r=r<<1;
# 		n=n>>1
# 	}
# 	return a
# }

def F(a,b):
	tmp = 0
	while True:
		if(b&1):
			tmp = D(tmp,a)
		a = a << 1
		b = b >> 1
		if b == 0:
			break
	return tmp

# function  G(r,n)
# {
# 	var a=0;
# 	while(r>=n)
# 	{
# 		r=E(r,n);
# 		a=D(a,1)
# 	}
# 	return a
# }
def G(a,b):
	tmp = 0
	while (a>=b):
		a = E(a,b) & 0xff
		tmp = D(tmp,1)
	return tmp


# Q(r,n,a,v)
# {
# 	for(var t=r;t<=n;t++)
# 	{
# 		if(a[t]!=v[t-r])
# 		{
# 			return false
# 		}
# 	}
# 	return true
# }




result = []
for i in range(24):
	result.append(0)
result[0] = 's'
result[1] = 'c'
result[2] = 't'
result[3] = 'f'
result[4] = '{'
result[6] = 'c'
result[16] = 'c'
result[7] = result[17] = 'r'
result[21] = result[22] = '!'
result[9] = 'P'
result[10] = 't'
result[11] = '_'
result[12] = 'I'
result[13] = 'n'
result[14] = '_'
result[15] = 'S'
result[18] = 'I'
result[19] = 'p'
result[20] = 'T'
result[22] = '!'
result[23] = '}'
print D(ord('s'),ord('t'))
print E(ord('s'),ord('c'))
for i in range(0x100):
	if E(ord('c'),i) == 0:
		print chr(i)

for i0 in range(0x20,0x80):
	for i1 in range(0x20,0x80):
		a = i0
		b = i1
		if E(F(a,2),G(66,b)) == 64:
			print chr(i0),chr(i1)

for i in range(0x100):
	a = i
	if F(a,a) == i:
		print chr(i)
# for i in range(24):
# 	print result[i],
# for i0 in range(0x100):
# 	for i1 in range(0x100):
# 		for i2 in range(0x100):
# 			a = i0
# 			b = i1
# 			c = i2
# 			#print i0,i1,i2
# 			if (D(a,c) == 231) and (E(a,b)==16):
# 				print chr(i0),chr(i1),chr(i2)


print G(1020,ord('s'))

for i0 in range(0x20,0x80):
	for i1 in range(0x20,0x80):
		a = i0
		b = i1
		if E(a,b) == 4:
			print chr(i0),chr(i1)

result[5] = '5'
result[8] = '1'
print ''.join(result)

# function  r(r)
# {
# 	var n=r;
# 	var a=H(n);				#length
# 	var v=J(a,24);		    #input_length = 24
# 	var t=K(n,0);			
# 	var u=K(n,1);
# 	var i=K(n,2);
# 	var e=K(n,3);
# 	var f=D(L(t),L(i));
# 	var o=E(L(t),L(u));
# 	var c=K(n,6);
# 	var l=K(n,7);
# 	var h=K(n,16);
# 	var w=K(n,17);
# 	var I=J(E(L(u),L(h)),0);
# 	var S=J(D(L(c),L(l)),D(L(h),L(w)));
# 	var _=J(E(L(u),L(c)),0);
# 	var g=K(n,21);
# 	var p=K(n,22);
# 	var s=J(E(F(L(g),2),G(66,L(p))),64);
# 	var P=Q(9,15,n,"Pt_In_S");
# 	var T=J(L(l),L("r"));
# 	var b=J(f,231);
# 	var d=J(o,16);
# 	var j=M(K(n,5));
# 	var k=J(G(M(O(N(L(e)),"0")),j),204);
# 	var m=M(K(n,8));
# 	var q=Q(18,20,n,"IpT");
# 	var x=J(E(j,m),4);
# 	var y=J(F(m,m),m);
# 	var z=J(D(L(K(n,4)),D(m,m)),L(K(n,23)));
# 	var A=J(L(u),99);
# 	var B=J(L(K(n,23)),125);
# 	var C=J(L(K(n,22)),33);
# 	return v&&I&&S&&_&&s&&P&&T&&b&&d&&k&&q&&x&&y&&z&&A&&B&&C
# }

