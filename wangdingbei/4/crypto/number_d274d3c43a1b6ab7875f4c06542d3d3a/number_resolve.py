import os
from gmpy2 import *
from pwn import *
import binascii as B

def get_num():
	ip_addr = "0.0.0.0"
	ip_port = 5884
	p = remote(ip_addr,ip_port)
	p.readuntil('it.\n')
	n1 = int(p.readline().strip('\n'))
	m1 = int(p.readline().strip('\n'))
	p.close()
	return n1,m1

if __name__ == '__main__':
	n1,m1 = get_num()
	n2,m2 = get_num()

	print n1,m1
	print n2,m2

	p = gcd(n1-n2,m1-m2)
	flag1 = n1%p
	flag2 = n2%p
	print "flag:" + str(B.a2b_hex(hex(flag1)[2:]))
	

