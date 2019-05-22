from pwn import *

# context.log_level = 'debug'


while 1:
# p = process('./babyre2',aslr=False)
	p=remote('139.180.215.222',20000)
	p.recvuntil('account:')
	p.sendline('aaaaaaaaaaaaaa')
	p.recvuntil('password:')
	p.send('\x10'+'\x20'*7)

	p.recvuntil('data:')
	data = '00'*9+'20'
	data = data.ljust(1024,'0')
	# print len(data)

	# attach(p)
	# raw_input()

	p.send(data)
	try:
		s = p.recvuntil('flag: ')
		print s
		s = p.recvline()
		print s
		print len(s)
		break
		# p.interactive()
	except:
		pass

# print i
# if 'rctf' in s:
# 	break
# p.close()

# p.interactive()